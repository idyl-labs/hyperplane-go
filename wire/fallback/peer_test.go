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
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// wireFrame is one fallback/1 frame as a raw peer sees it on the wire.
type wireFrame struct {
	typ     byte
	sid     uint32
	payload []byte
}

// encodeFrame renders header(9) || payload exactly as the protocol defines
// it, without the sender-side payload cap, so tests can build frames a
// conforming sender would refuse.
func encodeFrame(typ byte, sid uint32, payload []byte) []byte {
	b := make([]byte, headerLen, headerLen+len(payload))
	b[0] = typ
	binary.BigEndian.PutUint32(b[1:5], sid)
	binary.BigEndian.PutUint32(b[5:9], uint32(len(payload)))
	return append(b, payload...)
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }
func u64(v uint64) []byte { return binary.BigEndian.AppendUint64(nil, v) }

// rawPeer drives a Conn from the other end of a net.Pipe with hand-built
// frames and records every frame the Conn sends. net.Pipe is synchronous:
// a Write returns only once the Conn's read loop has consumed every byte,
// which lets a test order its assertions on events instead of sleeps.
type rawPeer struct {
	nc     net.Conn
	frames chan wireFrame
	done   chan struct{} // closed when the Conn's side of the pipe is gone
}

// newRawPeer wraps one end of a net.Pipe with mk (Client or Server) and
// returns the Conn and a raw peer on the other end. The peer reads every
// frame the Conn writes, so the Conn never blocks on its own writes.
func newRawPeer(t *testing.T, mk func(net.Conn, time.Duration) *Conn, idle time.Duration) (*Conn, *rawPeer) {
	t.Helper()
	local, remote := net.Pipe()
	c := mk(local, idle)
	p := &rawPeer{nc: remote, frames: make(chan wireFrame, 4096), done: make(chan struct{})}
	go p.drain()
	t.Cleanup(func() {
		_ = c.CloseWithError(0, "test done")
		_ = remote.Close()
		<-p.done
		<-c.Context().Done()
	})
	return c, p
}

func (p *rawPeer) drain() {
	defer close(p.done)
	hdr := make([]byte, headerLen)
	for {
		if _, err := io.ReadFull(p.nc, hdr); err != nil {
			return
		}
		f := wireFrame{typ: hdr[0], sid: binary.BigEndian.Uint32(hdr[1:5])}
		if n := binary.BigEndian.Uint32(hdr[5:9]); n > 0 {
			f.payload = make([]byte, n)
			if _, err := io.ReadFull(p.nc, f.payload); err != nil {
				return
			}
		}
		p.frames <- f
	}
}

// send writes one frame to the Conn. It returns an error once the Conn has
// closed its end.
func (p *rawPeer) send(typ byte, sid uint32, payload []byte) error {
	_, err := p.nc.Write(encodeFrame(typ, sid, payload))
	return err
}

func (p *rawPeer) mustSend(t *testing.T, typ byte, sid uint32, payload []byte) {
	t.Helper()
	if err := p.send(typ, sid, payload); err != nil {
		t.Fatalf("send frame type 0x%02x sid %d: %v", typ, sid, err)
	}
}

// sync returns once the Conn has finished handling every frame sent before
// it. The read loop consumes the PING header only after dispatching the
// previous frame, and a PING has no other effect on a Conn without an idle
// bound.
func (p *rawPeer) sync(t *testing.T) {
	t.Helper()
	p.mustSend(t, typePing, 0, nil)
}

// next returns the next frame the Conn wrote.
func (p *rawPeer) next(t *testing.T) wireFrame {
	t.Helper()
	select {
	case f := <-p.frames:
		return f
	case <-time.After(5 * time.Second):
		t.Fatal("the Conn wrote no frame")
		return wireFrame{}
	}
}

// expect returns the next frame and fails unless it has the given type and
// stream id.
func (p *rawPeer) expect(t *testing.T, typ byte, sid uint32) wireFrame {
	t.Helper()
	f := p.next(t)
	if f.typ != typ || f.sid != sid {
		t.Fatalf("frame = type 0x%02x sid %d len %d, want type 0x%02x sid %d", f.typ, f.sid, len(f.payload), typ, sid)
	}
	return f
}

// closeCause waits for c to close and returns its close cause.
func closeCause(t *testing.T, c *Conn) error {
	t.Helper()
	select {
	case <-c.Context().Done():
		return context.Cause(c.Context())
	case <-time.After(5 * time.Second):
		t.Fatal("the connection did not close")
		return nil
	}
}

// requireOpen fails if c has closed.
func requireOpen(t *testing.T, c *Conn) {
	t.Helper()
	if err := c.Context().Err(); err != nil {
		t.Fatalf("connection closed: %v", context.Cause(c.Context()))
	}
}

// acceptOne accepts one bidirectional stream with a generous bound.
func acceptOne(t *testing.T, c *Conn) *Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := c.AcceptStream(ctx)
	if err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	return s
}

// liveStreams reports how many streams c still tracks.
func liveStreams(c *Conn) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.streams)
}
