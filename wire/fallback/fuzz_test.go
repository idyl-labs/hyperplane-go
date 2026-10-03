// Copyright 2026 Idyl Labs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fallback

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// countingConn counts the bytes the Conn's read loop consumes from the
// transport and reports each time the loop asks for more.
type countingConn struct {
	net.Conn
	read    atomic.Int64
	reading atomic.Bool   // the read loop is inside Read
	entered chan struct{} // signaled on each Read entry
}

func (c *countingConn) Read(p []byte) (int, error) {
	c.reading.Store(true)
	select {
	case c.entered <- struct{}{}:
	default:
	}
	n, err := c.Conn.Read(p)
	c.read.Add(int64(n))
	c.reading.Store(false)
	return n, err
}

// waitQuiescent returns once the read loop has handled every one of the
// want bytes, which it has when it is back inside Read with all of them
// consumed, or once the connection has closed.
func (c *countingConn) waitQuiescent(conn *Conn, want int) {
	for {
		if c.reading.Load() && c.read.Load() == int64(want) {
			return
		}
		select {
		case <-c.entered:
		case <-conn.Context().Done():
			return
		}
	}
}

// readBound returns how many bytes of input a conforming reader may
// consume: everything, unless a header declares a payload over
// MaxFramePayload, in which case reading must stop at the end of that
// header. oversized reports whether such a header exists.
func readBound(data []byte) (bound int, oversized bool) {
	off := 0
	for off+headerLen <= len(data) {
		n := binary.BigEndian.Uint32(data[off+5 : off+9])
		if n > MaxFramePayload {
			return off + headerLen, true
		}
		off += headerLen + int(n)
	}
	return len(data), false
}

// readLoopsRunning counts goroutines currently inside a Conn read loop.
func readLoopsRunning() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	return bytes.Count(buf, []byte("fallback.(*Conn).readLoop("))
}

// waitReadLoopsGone waits until no Conn read loop is running.
func waitReadLoopsGone(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for readLoopsRunning() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("a Conn read loop is still running after its connection closed")
		}
		runtime.Gosched()
		time.Sleep(100 * time.Microsecond)
	}
}

// FuzzConnFrames writes arbitrary bytes into a Conn as its peer would and
// checks the reader's contract. The Conn either stays open or closes with
// ErrProtocol (or a peer CLOSE); it never panics; it never reads past a
// header that declares more than MaxFramePayload, so no frame allocates
// beyond the cap; no stream ever buffers more than InitialWindow bytes;
// and once closed, every goroutine it started, and every stream reader,
// has returned.
func FuzzConnFrames(f *testing.F) {
	seq := func(frames ...[]byte) []byte { return bytes.Join(frames, nil) }
	f.Add(seq(encodeFrame(typePing, 0, nil)), false)
	f.Add(seq(
		encodeFrame(typeOpenBidi, 1, nil),
		encodeFrame(typeData, 1, []byte("hello")),
		encodeFrame(typeWindow, 1, u32(16)),
		encodeFrame(typeFin, 1, nil),
	), false)
	f.Add(seq(
		encodeFrame(typeOpenUni, 2, nil),
		encodeFrame(typeData, 2, []byte("event")),
		encodeFrame(typeReset, 2, u64(4)),
		encodeFrame(typeData, 2, []byte("late")),
	), true)
	f.Add(seq(
		encodeFrame(typeOpenBidi, 1, nil),
		encodeFrame(typeData, 1, make([]byte, MaxFramePayload)),
	), false)
	f.Add(seq(encodeFrame(typeClose, 0, append(u64(0x10), "drain"...))), true)
	f.Add(seq(encodeFrame(typeOpenBidi, 2, nil)), false)                                    // wrong parity
	f.Add(seq(encodeFrame(typeOpenBidi, 3, nil), encodeFrame(typeOpenBidi, 1, nil)), false) // id reuse
	f.Add(seq(encodeFrame(typeData, 0, []byte("x"))), false)                                // stream frame on id 0
	f.Add(seq(encodeFrame(typeWindow, 1, []byte{1})), true)                                 // short WINDOW
	f.Add(seq(encodeFrame(0x42, 0, nil)), false)                                            // unknown type
	f.Add([]byte{typeData, 0, 0, 0, 1, 0, 1, 0, 1, 'x'}, false)                             // oversized length
	f.Add([]byte{typeData, 0, 0}, true)                                                     // truncated header

	f.Fuzz(func(t *testing.T, data []byte, asClient bool) {
		local, remote := net.Pipe()
		tc := &countingConn{Conn: local, entered: make(chan struct{}, 1)}
		mk := Server
		if asClient {
			mk = Client
		}
		c := mk(tc, 0)

		drained := make(chan struct{})
		go func() {
			defer close(drained)
			_, _ = io.Copy(io.Discard, remote)
		}()
		var readers sync.WaitGroup
		for _, accept := range []func(context.Context) (*Stream, error){c.AcceptStream, c.AcceptUniStream} {
			readers.Go(func() {
				for {
					s, err := accept(context.Background())
					if err != nil {
						return
					}
					readers.Go(func() { _, _ = io.Copy(io.Discard, s) })
				}
			})
		}

		// The write returns once the read loop has consumed every byte,
		// or with an error once the Conn has closed its end. The Conn is
		// closed locally only after it has handled all of them.
		_, _ = remote.Write(data)
		tc.waitQuiescent(c, len(data))

		c.mu.Lock()
		for _, s := range c.streams {
			s.mu.Lock()
			buffered := len(s.recvBuf)
			s.mu.Unlock()
			if buffered > InitialWindow {
				c.mu.Unlock()
				t.Fatalf("stream %d buffers %d bytes, over InitialWindow", s.id, buffered)
			}
		}
		c.mu.Unlock()

		_ = c.CloseWithError(0, "fuzz done")
		<-c.Context().Done()
		cause := context.Cause(c.Context())
		var ce *ConnError
		if !errors.Is(cause, ErrProtocol) && !errors.As(cause, &ce) {
			t.Fatalf("close cause %v (%T) is neither ErrProtocol nor a ConnError", cause, cause)
		}

		readers.Wait()
		_ = remote.Close()
		<-drained
		waitReadLoopsGone(t)

		bound, oversized := readBound(data)
		consumed := int(tc.read.Load())
		if consumed > bound {
			t.Fatalf("read %d bytes, past the bound %d set by an oversized header", consumed, bound)
		}
		if oversized && consumed == bound && bound < len(data) && !errors.Is(cause, ErrProtocol) {
			t.Fatalf("an oversized header was read but the cause is %v, want ErrProtocol", cause)
		}
	})
}
