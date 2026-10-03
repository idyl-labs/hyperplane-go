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
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// These tests run the fallback/1 stream multiplexer over a real loopback
// TCP pair. TLS is omitted because it does not change the multiplexing
// logic under test.

// pair returns a connected client and server Conn over loopback TCP with
// the given idle timeouts (zero disables idle detection on that side).
func pair(t *testing.T, idleClient, idleServer time.Duration) (*Conn, *Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	type res struct {
		c   net.Conn
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := ln.Accept()
		ch <- res{c, err}
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	r := <-ch
	if r.err != nil {
		t.Fatal(r.err)
	}
	client := Client(cc, idleClient)
	server := Server(r.c, idleServer)
	t.Cleanup(func() {
		_ = client.CloseWithError(0, "test done")
		_ = server.CloseWithError(0, "test done")
	})
	return client, server
}

func TestBidiRoundTrip(t *testing.T) {
	client, server := pair(t, 0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Write([]byte("hello from client")); err != nil {
		t.Fatal(err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := ss.Read(buf)
	if err != nil || string(buf[:n]) != "hello from client" {
		t.Fatalf("server read %q err %v", buf[:n], err)
	}
	if _, err := ss.Write([]byte("hello back")); err != nil {
		t.Fatal(err)
	}
	n, err = cs.Read(buf)
	if err != nil || string(buf[:n]) != "hello back" {
		t.Fatalf("client read %q err %v", buf[:n], err)
	}

	// Orderly half-close: FIN → EOF after the buffered bytes.
	if err := cs.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("want EOF after FIN, got %v", err)
	}
}

func TestUniStream(t *testing.T) {
	client, server := pair(t, 0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// A server-opened unidirectional stream, the direction the edge uses
	// to push to the client.
	us, err := server.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := us.Write([]byte("pushed")); err != nil {
		t.Fatal(err)
	}
	_ = us.Close()

	ur, err := client.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(ur)
	if err != nil || string(got) != "pushed" {
		t.Fatalf("uni read %q err %v", got, err)
	}
}

// TestWindowBackpressure checks that a sender past the credit window
// blocks and unblocks only when the consumer reads. Per-stream buffering
// stays bounded: a slow reader applies backpressure instead of growing an
// unbounded queue.
func TestWindowBackpressure(t *testing.T) {
	client, server := pair(t, 0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cs, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Write([]byte{1}); err != nil { // materialize at the peer
		t.Fatal(err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Fill the whole window (the 1 byte above included), then issue one
	// more write, which must block.
	fill := make([]byte, InitialWindow-1)
	if _, err := cs.Write(fill); err != nil {
		t.Fatal(err)
	}
	wrote := make(chan error, 1)
	go func() {
		_, err := cs.Write([]byte("overflow"))
		wrote <- err
	}()
	select {
	case err := <-wrote:
		t.Fatalf("write past the window returned (%v); must block", err)
	case <-time.After(300 * time.Millisecond):
	}

	// Consume; the blocked write completes.
	if _, err := io.ReadFull(ss, make([]byte, 1024)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatalf("unblocked write failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("write did not unblock after the consumer read")
	}
}

// TestResetTearsBothDirections checks that CancelWrite reaches the peer as
// ErrStreamReset on read and also cancels the local stream context.
func TestResetTearsBothDirections(t *testing.T) {
	client, server := pair(t, 0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cs.CancelWrite(42)

	buf := make([]byte, 16)
	deadline := time.Now().Add(5 * time.Second)
	for {
		_ = ss.SetReadDeadline(deadline)
		if _, err := ss.Read(buf); err != nil {
			if errors.Is(err, ErrStreamReset) {
				break
			}
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				// Buffered data may still drain first; a reset must land.
				t.Fatalf("want ErrStreamReset, got %v", err)
			}
			t.Fatal("reset never reached the peer")
		}
	}
	select {
	case <-cs.Context().Done():
	default:
		t.Fatal("reset must cancel the local stream context")
	}
}

// TestResetCarriesTypedCode checks that the RESET frame's u64 code
// surfaces as a typed StreamResetError on both ends: Remote on the peer
// that received the frame, local on the side that called CancelWrite or
// CancelRead. The error also satisfies errors.Is(err, ErrStreamReset) and
// keeps a stable message, so callers read the code from the typed error
// rather than parsing text.
func TestResetCarriesTypedCode(t *testing.T) {
	client, server := pair(t, 0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cs.CancelWrite(42)

	buf := make([]byte, 16)
	deadline := time.Now().Add(5 * time.Second)
	var got error
	for {
		_ = ss.SetReadDeadline(deadline)
		_, err := ss.Read(buf)
		if err == nil {
			continue // buffered data drains first; the reset must land
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatal("reset never reached the peer")
		}
		got = err
		break
	}
	var sre StreamResetError
	if !errors.As(got, &sre) {
		t.Fatalf("want StreamResetError, got %v (%T)", got, got)
	}
	if sre.Code != 42 || !sre.Remote {
		t.Fatalf("remote reset = %+v, want Code=42 Remote=true", sre)
	}
	if !errors.Is(got, ErrStreamReset) {
		t.Fatal("StreamResetError must keep satisfying errors.Is(_, ErrStreamReset)")
	}
	if want := "fallback: stream reset: code 42"; got.Error() != want {
		t.Fatalf("remote reset text = %q, want %q", got.Error(), want)
	}

	// The canceling side records the matching local error as its stream
	// cause.
	<-cs.Context().Done()
	cause := context.Cause(cs.Context())
	if !errors.As(cause, &sre) || sre.Code != 42 || sre.Remote {
		t.Fatalf("local reset cause = %v, want StreamResetError{Code: 42, Remote: false}", cause)
	}
	if !errors.Is(cause, ErrStreamReset) {
		t.Fatal("local StreamResetError must keep satisfying errors.Is(_, ErrStreamReset)")
	}
}

// TestStreamFramesRejectConnectionStreamID checks that a stream-scoped
// frame addressed to stream ID 0, which is reserved for the connection,
// closes the connection with ErrProtocol.
func TestStreamFramesRejectConnectionStreamID(t *testing.T) {
	cases := []struct {
		name    string
		typ     byte
		payload []byte
	}{
		{"data", typeData, []byte("x")},
		{"fin", typeFin, nil},
		{"reset", typeReset, binary.BigEndian.AppendUint64(nil, 7)},
		{"window", typeWindow, binary.BigEndian.AppendUint32(nil, 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := pair(t, 0, 0)
			if err := client.writeFrame(tc.typ, 0, tc.payload); err != nil {
				t.Fatalf("write malformed frame: %v", err)
			}
			select {
			case <-server.Context().Done():
			case <-time.After(2 * time.Second):
				t.Fatal("server accepted stream frame on connection stream id 0")
			}
			if !errors.Is(context.Cause(server.Context()), ErrProtocol) {
				t.Fatalf("want ErrProtocol, got %v", context.Cause(server.Context()))
			}
		})
	}
}

func TestCloseCarriesCode(t *testing.T) {
	client, server := pair(t, 0, 0)
	_ = client.CloseWithError(0x10, "drain")

	<-server.Context().Done()
	var ce *ConnError
	if !errors.As(context.Cause(server.Context()), &ce) {
		t.Fatalf("want ConnError cause, got %v", context.Cause(server.Context()))
	}
	if ce.Code != 0x10 || !ce.Remote || ce.Reason != "drain" {
		t.Fatalf("close cause wrong: %+v", ce)
	}

	// Local side records its own cause too.
	<-client.Context().Done()
	if !errors.As(context.Cause(client.Context()), &ce) || ce.Remote {
		t.Fatalf("local close cause wrong: %v", context.Cause(client.Context()))
	}
}

// TestIdleTimeoutAndPing checks that the transport detects a silent peer
// on its own, closing with IdleTimeoutError, and that PING frames alone
// keep an otherwise idle connection open. Idle detection is the backstop
// that ends a connection whose peer vanished without closing it.
func TestIdleTimeoutAndPing(t *testing.T) {
	client, server := pair(t, 0, 400*time.Millisecond)

	// PINGs at about half the idle window hold the connection open.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(150 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_ = client.SendKeepalive()
			}
		}
	}()
	select {
	case <-server.Context().Done():
		t.Fatal("pinged connection must survive the idle window")
	case <-time.After(time.Second):
	}
	close(stop)
	wg.Wait()

	// Silence past the window kills it with the idle cause.
	select {
	case <-server.Context().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("silent connection must idle out")
	}
	var idle IdleTimeoutError
	if !errors.As(context.Cause(server.Context()), &idle) {
		t.Fatalf("want IdleTimeoutError, got %v", context.Cause(server.Context()))
	}
}

func TestReadDeadline(t *testing.T) {
	client, server := pair(t, 0, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cs, err := client.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	ss, err := server.AcceptStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(ss, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	_ = ss.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	start := time.Now()
	if _, err := ss.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want ErrDeadlineExceeded, got %v", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("deadline fired far too late")
	}
	// Clearing the deadline restores blocking reads.
	_ = ss.SetReadDeadline(time.Time{})
	got := make(chan error, 1)
	go func() {
		_, err := ss.Read(make([]byte, 1))
		got <- err
	}()
	if _, err := cs.Write([]byte("y")); err != nil {
		t.Fatal(err)
	}
	if err := <-got; err != nil {
		t.Fatalf("post-deadline read: %v", err)
	}
}
