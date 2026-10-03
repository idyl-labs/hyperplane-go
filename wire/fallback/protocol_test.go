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
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

// These tests drive a Conn frame by frame from a raw peer, so every
// refusal and boundary of the fallback/1 frame contract is exercised
// exactly as a misbehaving or adversarial peer would trigger it.

// TestReadFrameAcceptsPayloadAtMaxFramePayload checks that a frame whose
// payload is exactly MaxFramePayload is accepted and delivered intact: the
// cap is inclusive.
func TestReadFrameAcceptsPayloadAtMaxFramePayload(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	payload := bytes.Repeat([]byte{0xa5}, MaxFramePayload)
	p.mustSend(t, typeOpenBidi, 1, nil)
	p.mustSend(t, typeData, 1, payload)
	p.sync(t)
	requireOpen(t, c)

	s := acceptOne(t, c)
	got := make([]byte, MaxFramePayload)
	if _, err := io.ReadFull(s, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload at the cap was not delivered intact")
	}
}

// TestReadFrameRefusesOversizedLength checks that a header declaring one
// byte more than MaxFramePayload closes the connection with ErrProtocol
// from the header alone, before any payload is read or allocated.
func TestReadFrameRefusesOversizedLength(t *testing.T) {
	for _, typ := range []byte{typeData, typePing, 0x7f} {
		c, p := newRawPeer(t, Server, 0)
		hdr := encodeFrame(typ, 1, nil)
		hdr[5], hdr[6], hdr[7], hdr[8] = 0, 1, 0, 1 // MaxFramePayload + 1
		if _, err := p.nc.Write(hdr); err != nil {
			t.Fatal(err)
		}
		if cause := closeCause(t, c); !errors.Is(cause, ErrProtocol) {
			t.Fatalf("type 0x%02x: cause = %v, want ErrProtocol", typ, cause)
		}
	}
}

// TestWriteFrameRefusesOversizedPayload checks the sender-side cap: a frame
// over MaxFramePayload is refused with ErrProtocol and never reaches the
// wire, the connection stays open, and a frame exactly at the cap is sent.
func TestWriteFrameRefusesOversizedPayload(t *testing.T) {
	c, p := newRawPeer(t, Client, 0)
	if err := c.writeFrame(typeData, 1, make([]byte, MaxFramePayload+1)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("oversized write = %v, want ErrProtocol", err)
	}
	requireOpen(t, c)
	if err := c.writeFrame(typeData, 1, make([]byte, MaxFramePayload)); err != nil {
		t.Fatalf("write at the cap: %v", err)
	}
	if f := p.expect(t, typeData, 1); len(f.payload) != MaxFramePayload {
		t.Fatalf("payload length = %d, want %d", len(f.payload), MaxFramePayload)
	}
}

// TestOpenRefusesWrongParity checks stream id parity: a client accepts only
// even peer-opened ids and a server only odd ones, and id 0 is never a
// stream. A peer that opens with the wrong parity would collide with this
// side's own ids, so the connection closes with ErrProtocol.
func TestOpenRefusesWrongParity(t *testing.T) {
	cases := []struct {
		name string
		mk   func(net.Conn, time.Duration) *Conn
		sid  uint32
		ok   bool
	}{
		{"server accepts odd", Server, 1, true},
		{"server refuses even", Server, 2, false},
		{"server refuses zero", Server, 0, false},
		{"client accepts even", Client, 2, true},
		{"client refuses odd", Client, 1, false},
		{"client refuses zero", Client, 0, false},
	}
	for _, tc := range cases {
		for _, typ := range []byte{typeOpenBidi, typeOpenUni} {
			t.Run(fmt.Sprintf("%s/type 0x%02x", tc.name, typ), func(t *testing.T) {
				c, p := newRawPeer(t, tc.mk, 0)
				if !tc.ok {
					_ = p.send(typ, tc.sid, nil)
					if cause := closeCause(t, c); !errors.Is(cause, ErrProtocol) {
						t.Fatalf("cause = %v, want ErrProtocol", cause)
					}
					return
				}
				p.mustSend(t, typ, tc.sid, nil)
				p.sync(t)
				requireOpen(t, c)
				accept := c.AcceptStream
				if typ == typeOpenUni {
					accept = c.AcceptUniStream
				}
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if _, err := accept(ctx); err != nil {
					t.Fatalf("accept: %v", err)
				}
			})
		}
	}
}

// TestOpenRefusesNonIncreasingStreamID checks that peer-opened ids must
// strictly increase. Reopening an id, or opening below the highest id seen,
// would resurrect a finished stream, so the connection closes with
// ErrProtocol.
func TestOpenRefusesNonIncreasingStreamID(t *testing.T) {
	for _, seq := range [][]uint32{{1, 1}, {5, 3}} {
		c, p := newRawPeer(t, Server, 0)
		p.mustSend(t, typeOpenBidi, seq[0], nil)
		_ = p.send(typeOpenUni, seq[1], nil)
		if cause := closeCause(t, c); !errors.Is(cause, ErrProtocol) {
			t.Fatalf("opens %v: cause = %v, want ErrProtocol", seq, cause)
		}
	}
}

// TestLocalStreamIDsFollowParity checks the ids this side assigns: a client
// opens 1, 3, 5, ... and a server 2, 4, 6, ..., shared across bidirectional
// and unidirectional streams, and an OPEN frame carries no payload.
func TestLocalStreamIDsFollowParity(t *testing.T) {
	for _, tc := range []struct {
		mk    func(net.Conn, time.Duration) *Conn
		first uint32
	}{{Client, 1}, {Server, 2}} {
		c, p := newRawPeer(t, tc.mk, 0)
		ctx := context.Background()
		if _, err := c.OpenStreamSync(ctx); err != nil {
			t.Fatal(err)
		}
		if _, err := c.OpenUniStream(); err != nil {
			t.Fatal(err)
		}
		if _, err := c.OpenStreamSync(ctx); err != nil {
			t.Fatal(err)
		}
		for i, typ := range []byte{typeOpenBidi, typeOpenUni, typeOpenBidi} {
			f := p.expect(t, typ, tc.first+uint32(2*i))
			if len(f.payload) != 0 {
				t.Fatalf("OPEN frame carries %d payload bytes", len(f.payload))
			}
		}
	}
}

// TestUnknownFrameTypeClosesConnection checks that a frame type outside the
// protocol closes the connection with ErrProtocol rather than being
// skipped, so a peer cannot smuggle frames this side does not understand.
func TestUnknownFrameTypeClosesConnection(t *testing.T) {
	for _, typ := range []byte{0x00, typeClose + 1, 0xff} {
		c, p := newRawPeer(t, Server, 0)
		_ = p.send(typ, 0, nil)
		if cause := closeCause(t, c); !errors.Is(cause, ErrProtocol) {
			t.Fatalf("type 0x%02x: cause = %v, want ErrProtocol", typ, cause)
		}
	}
}

// TestMalformedControlPayloadsCloseConnection checks the fixed payload
// sizes of control frames: RESET carries exactly 8 bytes, WINDOW exactly 4,
// and CLOSE at least 8. Any other length closes the connection with
// ErrProtocol, whether or not the stream exists.
func TestMalformedControlPayloadsCloseConnection(t *testing.T) {
	cases := []struct {
		name    string
		typ     byte
		sid     uint32
		payload []byte
	}{
		{"reset short", typeReset, 1, make([]byte, 7)},
		{"reset long", typeReset, 1, make([]byte, 9)},
		{"reset empty", typeReset, 1, nil},
		{"window short", typeWindow, 1, make([]byte, 3)},
		{"window long", typeWindow, 1, make([]byte, 5)},
		{"close short", typeClose, 0, make([]byte, 7)},
		{"close empty", typeClose, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p := newRawPeer(t, Server, 0)
			p.mustSend(t, typeOpenBidi, 1, nil)
			_ = p.send(tc.typ, tc.sid, tc.payload)
			if cause := closeCause(t, c); !errors.Is(cause, ErrProtocol) {
				t.Fatalf("cause = %v, want ErrProtocol", cause)
			}
		})
	}
}

// TestRemoteCloseCarriesCodeAndReason checks the CLOSE frame decoding: the
// first 8 bytes are the big-endian application code and the rest is the
// reason, which may be empty. The cause is a remote *ConnError, not a
// protocol violation.
func TestRemoteCloseCarriesCodeAndReason(t *testing.T) {
	for _, reason := range []string{"", "going away"} {
		c, p := newRawPeer(t, Client, 0)
		_ = p.send(typeClose, 0, append(u64(0x0102030405060708), reason...))
		cause := closeCause(t, c)
		var ce *ConnError
		if !errors.As(cause, &ce) {
			t.Fatalf("cause = %v, want *ConnError", cause)
		}
		if ce.Code != 0x0102030405060708 || ce.Reason != reason || !ce.Remote {
			t.Fatalf("cause = %+v, want code 0x0102030405060708 reason %q remote", ce, reason)
		}
		if errors.Is(cause, ErrProtocol) {
			t.Fatal("an orderly remote close must not classify as a protocol violation")
		}
	}
}

// TestCloseWithErrorEncodesCodeAndReason checks the CLOSE frame this side
// sends: connection stream id 0 and payload u64 code || reason. A second
// CloseWithError returns nil, sends nothing, and keeps the first cause.
func TestCloseWithErrorEncodesCodeAndReason(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	if err := c.CloseWithError(0x1234, "drain"); err != nil {
		t.Fatalf("CloseWithError = %v, want nil", err)
	}
	f := p.expect(t, typeClose, 0)
	if want := append(u64(0x1234), "drain"...); !bytes.Equal(f.payload, want) {
		t.Fatalf("CLOSE payload = %x, want %x", f.payload, want)
	}
	if err := c.CloseWithError(0x9, "again"); err != nil {
		t.Fatalf("second CloseWithError = %v, want nil", err)
	}
	var ce *ConnError
	if cause := closeCause(t, c); !errors.As(cause, &ce) || ce.Code != 0x1234 || ce.Reason != "drain" || ce.Remote {
		t.Fatalf("cause = %v, want local ConnError 0x1234 drain", cause)
	}
	<-p.done // the Conn closed its end; the peer has read everything it sent
	if n := len(p.frames); n != 0 {
		t.Fatalf("second CloseWithError sent %d more frames", n)
	}
}

// TestFramesForUnknownStreamsAreIgnored checks that DATA, FIN, RESET and
// WINDOW for a stream this side does not know are dropped without closing
// the connection. Such frames legitimately cross a RESET in flight.
func TestFramesForUnknownStreamsAreIgnored(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeData, 7, []byte("late"))
	p.mustSend(t, typeFin, 7, nil)
	p.mustSend(t, typeReset, 7, u64(3))
	p.mustSend(t, typeWindow, 7, u32(10))
	p.sync(t)
	requireOpen(t, c)
	if n := liveStreams(c); n != 0 {
		t.Fatalf("frames for an unknown stream created %d streams", n)
	}
}

// TestPeerDataPastWindowClosesConnection checks credit enforcement on
// receive: a peer may send exactly InitialWindow unread bytes on a stream,
// and one byte more is a protocol violation that closes the connection,
// so a stream's receive buffer can never exceed its window.
func TestPeerDataPastWindowClosesConnection(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeOpenBidi, 1, nil)
	chunk := make([]byte, MaxFramePayload)
	for sent := 0; sent < InitialWindow; sent += len(chunk) {
		p.mustSend(t, typeData, 1, chunk)
	}
	p.sync(t)
	requireOpen(t, c)
	s := acceptOne(t, c)

	_ = p.send(typeData, 1, []byte{0})
	if cause := closeCause(t, c); !errors.Is(cause, ErrProtocol) {
		t.Fatalf("cause = %v, want ErrProtocol", cause)
	}
	<-s.Context().Done()
	if cause := context.Cause(s.Context()); !errors.Is(cause, ErrConnClosed) || !errors.Is(cause, ErrProtocol) {
		t.Fatalf("stream cause = %v, want ErrConnClosed wrapping ErrProtocol", cause)
	}
}

// TestReadReplenishesPeerCredit checks WINDOW replenishment: each Read
// grants the peer exactly the number of bytes the consumer took, on the
// stream's own id.
func TestReadReplenishesPeerCredit(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeOpenBidi, 1, nil)
	p.mustSend(t, typeData, 1, []byte("0123456789"))
	s := acceptOne(t, c)

	for _, want := range []uint32{4, 6} {
		buf := make([]byte, want)
		if n, err := s.Read(buf); err != nil || uint32(n) != want {
			t.Fatalf("Read = %d, %v; want %d", n, err, want)
		}
		f := p.expect(t, typeWindow, 1)
		if !bytes.Equal(f.payload, u32(want)) {
			t.Fatalf("WINDOW payload = %x, want increment %d", f.payload, want)
		}
	}
}

// TestWriteSplitsAtMaxFramePayload checks that a Write larger than one
// frame is carried as consecutive DATA frames of at most MaxFramePayload
// bytes that reassemble to the original bytes.
func TestWriteSplitsAtMaxFramePayload(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeOpenBidi, 1, nil)
	s := acceptOne(t, c)

	msg := make([]byte, MaxFramePayload+34464)
	for i := range msg {
		msg[i] = byte(i)
	}
	if n, err := s.Write(msg); err != nil || n != len(msg) {
		t.Fatalf("Write = %d, %v", n, err)
	}
	first := p.expect(t, typeData, 1)
	second := p.expect(t, typeData, 1)
	if len(first.payload) != MaxFramePayload || len(second.payload) != 34464 {
		t.Fatalf("frame sizes = %d, %d", len(first.payload), len(second.payload))
	}
	if !bytes.Equal(append(first.payload, second.payload...), msg) {
		t.Fatal("DATA frames do not reassemble to the written bytes")
	}
}

// TestWriteHonoursPeerCredit checks send-side flow control precisely: a
// stream sends at most InitialWindow bytes before credit, then exactly as
// many bytes as each WINDOW grants, and nothing while credit is zero.
func TestWriteHonoursPeerCredit(t *testing.T) {
	c, p := newRawPeer(t, Client, 0)
	s, err := c.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.expect(t, typeOpenBidi, 1)

	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := s.Write(make([]byte, InitialWindow+8))
		done <- result{n, err}
	}()
	for sent := 0; sent < InitialWindow; {
		sent += len(p.expect(t, typeData, 1).payload)
	}

	p.mustSend(t, typeWindow, 1, u32(3))
	if f := p.expect(t, typeData, 1); len(f.payload) != 3 {
		t.Fatalf("sent %d bytes on 3 bytes of credit", len(f.payload))
	}
	// Credit is zero again: the next frame on the wire is this PING, not
	// DATA.
	if err := c.SendKeepalive(); err != nil {
		t.Fatal(err)
	}
	p.expect(t, typePing, 0)

	p.mustSend(t, typeWindow, 1, u32(100))
	if f := p.expect(t, typeData, 1); len(f.payload) != 5 {
		t.Fatalf("final chunk = %d bytes, want 5", len(f.payload))
	}
	if r := <-done; r.err != nil || r.n != InitialWindow+8 {
		t.Fatalf("Write = %d, %v", r.n, r.err)
	}
}

// TestBlockedWriteEnds checks that a Write blocked at zero credit returns,
// with the bytes already sent counted, when the stream is closed locally,
// reset by the peer, or its connection closes. A writer is never stranded.
func TestBlockedWriteEnds(t *testing.T) {
	cases := []struct {
		name  string
		end   func(t *testing.T, c *Conn, p *rawPeer, s *Stream)
		check func(t *testing.T, err error)
	}{
		{
			"local close",
			func(t *testing.T, _ *Conn, _ *rawPeer, s *Stream) {
				t.Helper()
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			},
			func(t *testing.T, err error) {
				t.Helper()
				if err == nil || errors.Is(err, ErrStreamReset) || errors.Is(err, ErrConnClosed) {
					t.Fatalf("err = %v, want a write-after-close error", err)
				}
			},
		},
		{
			"remote reset",
			func(t *testing.T, _ *Conn, p *rawPeer, _ *Stream) {
				t.Helper()
				p.mustSend(t, typeReset, 1, u64(9))
			},
			func(t *testing.T, err error) {
				t.Helper()
				var sre StreamResetError
				if !errors.As(err, &sre) || sre.Code != 9 || !sre.Remote {
					t.Fatalf("err = %v, want remote StreamResetError code 9", err)
				}
			},
		},
		{
			"connection close",
			func(t *testing.T, c *Conn, _ *rawPeer, _ *Stream) {
				t.Helper()
				_ = c.CloseWithError(5, "bye")
			},
			func(t *testing.T, err error) {
				t.Helper()
				var ce *ConnError
				if !errors.Is(err, ErrConnClosed) || !errors.As(err, &ce) || ce.Code != 5 {
					t.Fatalf("err = %v, want ErrConnClosed with ConnError code 5", err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p := newRawPeer(t, Client, 0)
			s, err := c.OpenStreamSync(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			p.expect(t, typeOpenBidi, 1)
			type result struct {
				n   int
				err error
			}
			done := make(chan result, 1)
			go func() {
				n, err := s.Write(make([]byte, InitialWindow+1))
				done <- result{n, err}
			}()
			for sent := 0; sent < InitialWindow; {
				sent += len(p.expect(t, typeData, 1).payload)
			}
			tc.end(t, c, p, s)
			r := <-done
			if r.n != InitialWindow {
				t.Fatalf("Write reported %d bytes, want %d sent before blocking", r.n, InitialWindow)
			}
			tc.check(t, r.err)
		})
	}
}

// TestCancelReadResetsBothDirections checks the local reset contract: the
// peer receives one RESET carrying the code, local Read and Write return a
// local StreamResetError, Close becomes a no-op, a second cancel sends
// nothing, and the stream is released.
func TestCancelReadResetsBothDirections(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeOpenBidi, 1, nil)
	s := acceptOne(t, c)

	s.CancelRead(7)
	if f := p.expect(t, typeReset, 1); !bytes.Equal(f.payload, u64(7)) {
		t.Fatalf("RESET payload = %x, want code 7", f.payload)
	}
	want := StreamResetError{Code: 7}
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, want) { // exact code and side
		t.Fatalf("Read = %v, want %v", err, want)
	}
	if n, err := s.Write([]byte("x")); n != 0 || !errors.Is(err, ErrStreamReset) {
		t.Fatalf("Write = %d, %v; want 0, ErrStreamReset", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close after reset = %v, want nil", err)
	}
	s.CancelWrite(8)
	if err := c.SendKeepalive(); err != nil {
		t.Fatal(err)
	}
	p.expect(t, typePing, 0) // no second RESET and no FIN went out
	<-s.Context().Done()
	if cause := context.Cause(s.Context()); !errors.Is(cause, want) {
		t.Fatalf("stream cause = %v, want %v", cause, want)
	}
	if n := liveStreams(c); n != 0 {
		t.Fatalf("reset stream still tracked (%d streams)", n)
	}
	// Late data from the peer for the reset stream is dropped.
	p.mustSend(t, typeData, 1, []byte("late"))
	p.sync(t)
	requireOpen(t, c)
}

// TestRemoteResetUnblocksRead checks that a RESET from the peer wakes a
// blocked Read with a remote StreamResetError and cancels the stream
// context with the same cause.
func TestRemoteResetUnblocksRead(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeOpenBidi, 1, nil)
	s := acceptOne(t, c)

	got := make(chan error, 1)
	go func() {
		_, err := s.Read(make([]byte, 1))
		got <- err
	}()
	p.mustSend(t, typeReset, 1, u64(5))
	want := StreamResetError{Code: 5, Remote: true}
	if err := <-got; !errors.Is(err, want) {
		t.Fatalf("Read = %v, want %v", err, want)
	}
	// The stream's context is canceled just after blocked readers wake, so
	// wait for it before reading its cause.
	<-s.Context().Done()
	if cause := context.Cause(s.Context()); !errors.Is(cause, want) {
		t.Fatalf("stream cause = %v, want %v", cause, want)
	}
}

// TestFinDeliversBufferedDataThenEOF checks the half-close contract on
// receive: buffered bytes are read first, then io.EOF, the stream context
// stays live after an orderly FIN, and later DATA is dropped.
func TestFinDeliversBufferedDataThenEOF(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeOpenBidi, 1, nil)
	p.mustSend(t, typeData, 1, []byte("abc"))
	p.mustSend(t, typeFin, 1, nil)
	p.mustSend(t, typeData, 1, []byte("after fin"))
	p.sync(t)
	requireOpen(t, c)

	s := acceptOne(t, c)
	got, err := io.ReadAll(s)
	if err != nil || string(got) != "abc" {
		t.Fatalf("ReadAll = %q, %v; want \"abc\"", got, err)
	}
	if err := s.Context().Err(); err != nil {
		t.Fatalf("FIN canceled the stream context: %v", context.Cause(s.Context()))
	}
	// The reverse direction stays writable after the peer's FIN.
	if _, err := s.Write([]byte("reply")); err != nil {
		t.Fatalf("Write after peer FIN: %v", err)
	}
}

// TestStreamReleasedWhenBothSidesFinish checks resource release: a stream is
// dropped from the connection once both directions have finished and its
// buffer is drained, in either order of FINs.
func TestStreamReleasedWhenBothSidesFinish(t *testing.T) {
	t.Run("peer fin first", func(t *testing.T) {
		c, p := newRawPeer(t, Server, 0)
		p.mustSend(t, typeOpenBidi, 1, nil)
		p.mustSend(t, typeFin, 1, nil)
		s := acceptOne(t, c)
		if _, err := s.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
			t.Fatalf("Read = %v, want EOF", err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		p.expect(t, typeFin, 1)
		if n := liveStreams(c); n != 0 {
			t.Fatalf("finished stream still tracked (%d streams)", n)
		}
	})
	t.Run("local fin first", func(t *testing.T) {
		c, p := newRawPeer(t, Client, 0)
		s, err := c.OpenStreamSync(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		p.mustSend(t, typeFin, 1, nil)
		p.sync(t)
		if n := liveStreams(c); n != 0 {
			t.Fatalf("finished stream still tracked (%d streams)", n)
		}
	})
	t.Run("uni drained after fin", func(t *testing.T) {
		c, p := newRawPeer(t, Server, 0)
		p.mustSend(t, typeOpenUni, 1, nil)
		p.mustSend(t, typeData, 1, []byte("event"))
		p.mustSend(t, typeFin, 1, nil)
		p.sync(t)
		if n := liveStreams(c); n != 1 {
			t.Fatalf("undrained stream released early (%d streams)", n)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := c.AcceptUniStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := io.ReadAll(s); err != nil || string(got) != "event" {
			t.Fatalf("ReadAll = %q, %v", got, err)
		}
		if n := liveStreams(c); n != 0 {
			t.Fatalf("drained stream still tracked (%d streams)", n)
		}
	})
}

// TestWriteAfterCloseIsRefused checks that Close half-closes the send side
// once: a later Write fails without sending, and a second Close returns nil
// without sending a second FIN.
func TestWriteAfterCloseIsRefused(t *testing.T) {
	c, p := newRawPeer(t, Client, 0)
	s, err := c.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.expect(t, typeOpenBidi, 1)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	p.expect(t, typeFin, 1)
	if n, err := s.Write([]byte("x")); n != 0 || err == nil {
		t.Fatalf("Write after Close = %d, %v; want 0 and an error", n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close = %v, want nil", err)
	}
	if err := c.SendKeepalive(); err != nil {
		t.Fatal(err)
	}
	p.expect(t, typePing, 0)
}

// TestUniStreamDirections checks that a unidirectional stream is send-only
// for its opener and receive-only for its acceptor: the opener's Read
// reports EOF at once, and the acceptor's Write is refused.
func TestUniStreamDirections(t *testing.T) {
	c, p := newRawPeer(t, Client, 0)
	s, err := c.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	p.expect(t, typeOpenUni, 1)
	if _, err := s.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("opener Read = %v, want EOF", err)
	}
	// Data from the peer on the opener's send-only stream is dropped.
	p.mustSend(t, typeData, 1, []byte("x"))
	p.sync(t)
	requireOpen(t, c)

	p.mustSend(t, typeOpenUni, 2, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := c.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := r.Write([]byte("x")); n != 0 || err == nil {
		t.Fatalf("acceptor Write = %d, %v; want a refusal", n, err)
	}
}

// TestAcceptBacklogShedsExcessStreams checks the accept backlog bound: at
// most 64 peer-opened streams of each kind wait for Accept, a further open
// is reset with code 0 instead of being buffered, the connection stays
// open, and accepting frees room for new streams.
func TestAcceptBacklogShedsExcessStreams(t *testing.T) {
	for _, typ := range []byte{typeOpenBidi, typeOpenUni} {
		c, p := newRawPeer(t, Server, 0)
		accept := c.AcceptStream
		if typ == typeOpenUni {
			accept = c.AcceptUniStream
		}
		sid := uint32(1)
		for range acceptBacklog {
			p.mustSend(t, typ, sid, nil)
			sid += 2
		}
		shed := sid
		p.mustSend(t, typ, shed, nil)
		if f := p.expect(t, typeReset, shed); !bytes.Equal(f.payload, u64(0)) {
			t.Fatalf("shed RESET payload = %x, want code 0", f.payload)
		}
		requireOpen(t, c)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		for want := uint32(1); want < shed; want += 2 {
			s, err := accept(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if s.id != want {
				t.Fatalf("accepted stream %d, want %d", s.id, want)
			}
		}
		p.mustSend(t, typ, shed+2, nil)
		s, err := accept(ctx)
		cancel()
		if err != nil {
			t.Fatalf("accept after draining the backlog: %v", err)
		}
		if s.id != shed+2 {
			t.Fatalf("accepted stream %d after draining the backlog, want %d", s.id, shed+2)
		}
	}
}

// TestAcceptHonoursContext checks that Accept returns the caller's context
// error when it ends first, and leaves the connection open.
func TestAcceptHonoursContext(t *testing.T) {
	c, _ := newRawPeer(t, Server, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.AcceptStream(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("AcceptStream = %v, want context.Canceled", err)
	}
	dctx, dcancel := context.WithDeadline(context.Background(), time.Now())
	defer dcancel()
	if _, err := c.AcceptUniStream(dctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptUniStream = %v, want context.DeadlineExceeded", err)
	}
	requireOpen(t, c)
}

// TestOpenStreamSyncHonoursContext checks that a done context refuses the
// open before any frame is sent and without consuming a stream id.
func TestOpenStreamSyncHonoursContext(t *testing.T) {
	c, p := newRawPeer(t, Client, 0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, err := c.OpenStreamSync(ctx); !errors.Is(err, context.Canceled) || s != nil {
		t.Fatalf("OpenStreamSync returned stream %t, err %v; want no stream, context.Canceled", s != nil, err)
	}
	if _, err := c.OpenStreamSync(context.Background()); err != nil {
		t.Fatal(err)
	}
	p.expect(t, typeOpenBidi, 1)
}

// TestOperationsAfterCloseReportErrConnClosed checks that every connection
// operation after a close fails with ErrConnClosed and carries the close
// cause, so callers can both detect and classify the closed connection.
func TestOperationsAfterCloseReportErrConnClosed(t *testing.T) {
	c, _ := newRawPeer(t, Client, 0)
	_ = c.CloseWithError(3, "bye")
	ctx := context.Background()
	ops := map[string]func() error{
		"OpenStreamSync":  func() error { _, err := c.OpenStreamSync(ctx); return err },
		"OpenUniStream":   func() error { _, err := c.OpenUniStream(); return err },
		"AcceptStream":    func() error { _, err := c.AcceptStream(ctx); return err },
		"AcceptUniStream": func() error { _, err := c.AcceptUniStream(ctx); return err },
		"SendKeepalive":   c.SendKeepalive,
	}
	for name, op := range ops {
		err := op()
		var ce *ConnError
		if !errors.Is(err, ErrConnClosed) || !errors.As(err, &ce) || ce.Code != 3 {
			t.Errorf("%s = %v, want ErrConnClosed carrying ConnError code 3", name, err)
		}
	}
}

// TestConnCloseTerminatesStreams checks that closing the connection ends
// every stream: a blocked Read wakes with ErrConnClosed carrying the close
// cause, and each stream context is canceled with that error.
func TestConnCloseTerminatesStreams(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.mustSend(t, typeOpenBidi, 1, nil)
	in := acceptOne(t, c)
	out, err := c.OpenUniStream()
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		_, err := in.Read(make([]byte, 1))
		got <- err
	}()
	_ = c.CloseWithError(0x10, "drain")
	var ce *ConnError
	if err := <-got; !errors.Is(err, ErrConnClosed) || !errors.As(err, &ce) || ce.Code != 0x10 {
		t.Fatalf("blocked Read = %v, want ErrConnClosed carrying ConnError 0x10", err)
	}
	for _, s := range []*Stream{in, out} {
		<-s.Context().Done()
		if cause := context.Cause(s.Context()); !errors.Is(cause, ErrConnClosed) {
			t.Fatalf("stream cause = %v, want ErrConnClosed", cause)
		}
	}
	if n := liveStreams(c); n != 0 {
		t.Fatalf("closed connection still tracks %d streams", n)
	}
}

// TestPeerDisconnectClosesConnection checks that losing the transport
// closes the connection with the read error as its cause: a clean
// disconnect between frames is io.EOF, and a disconnect inside a header or
// payload is io.ErrUnexpectedEOF.
func TestPeerDisconnectClosesConnection(t *testing.T) {
	cases := []struct {
		name    string
		partial []byte
		want    error
	}{
		{"between frames", nil, io.EOF},
		{"inside header", encodeFrame(typeData, 1, nil)[:5], io.ErrUnexpectedEOF},
		{"inside payload", encodeFrame(typeData, 1, []byte("0123456789"))[:headerLen+3], io.ErrUnexpectedEOF},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, p := newRawPeer(t, Server, 0)
			p.mustSend(t, typeOpenBidi, 1, nil)
			if len(tc.partial) > 0 {
				if _, err := p.nc.Write(tc.partial); err != nil {
					t.Fatal(err)
				}
			}
			_ = p.nc.Close()
			if cause := closeCause(t, c); !errors.Is(cause, tc.want) {
				t.Fatalf("cause = %v, want %v", cause, tc.want)
			}
		})
	}
}

// failingWriteConn is a transport whose writes fail, standing in for a
// connection that broke under the sender.
type failingWriteConn struct {
	net.Conn
	err error
}

func (f failingWriteConn) Write([]byte) (int, error) { return 0, f.err }

// TestWriteFailureClosesConnection checks that a transport write error
// closes the whole connection: the failing call returns ErrConnClosed, and
// the connection's cause wraps the transport error.
func TestWriteFailureClosesConnection(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	broken := errors.New("transport broke")
	c := Client(failingWriteConn{Conn: local, err: broken}, 0)

	if _, err := c.OpenStreamSync(context.Background()); !errors.Is(err, ErrConnClosed) || !errors.Is(err, broken) {
		t.Fatalf("OpenStreamSync = %v, want ErrConnClosed wrapping the transport error", err)
	}
	if cause := closeCause(t, c); !errors.Is(cause, broken) {
		t.Fatalf("cause = %v, want the transport error", cause)
	}
	if _, err := c.OpenUniStream(); !errors.Is(err, ErrConnClosed) {
		t.Fatalf("OpenUniStream after failure = %v, want ErrConnClosed", err)
	}
}

// TestStreamWriteFailureClosesConnection checks that a transport write
// error during a stream Write fails that Write with ErrConnClosed wrapping
// the transport error, counts no bytes as written, and closes the
// connection.
func TestStreamWriteFailureClosesConnection(t *testing.T) {
	local, remote := net.Pipe()
	defer func() { _ = remote.Close() }()
	broken := errors.New("transport broke")
	c := Server(failingWriteConn{Conn: local, err: broken}, 0)

	if _, err := remote.Write(encodeFrame(typeOpenBidi, 1, nil)); err != nil {
		t.Fatal(err)
	}
	s := acceptOne(t, c)
	if n, err := s.Write([]byte("x")); n != 0 || !errors.Is(err, ErrConnClosed) || !errors.Is(err, broken) {
		t.Fatalf("Write = %d, %v; want 0 and ErrConnClosed wrapping the transport error", n, err)
	}
	if cause := closeCause(t, c); !errors.Is(cause, broken) {
		t.Fatalf("cause = %v, want the transport error", cause)
	}
}

// TestClientIdleTimeout checks the idle bound on the dialing side: a peer
// that sends nothing closes a Client with IdleTimeoutError, and a pending
// Accept reports ErrConnClosed carrying that cause.
func TestClientIdleTimeout(t *testing.T) {
	c, _ := newRawPeer(t, Client, 50*time.Millisecond)
	_, err := c.AcceptStream(context.Background())
	var idle IdleTimeoutError
	if !errors.Is(err, ErrConnClosed) || !errors.As(err, &idle) {
		t.Fatalf("AcceptStream = %v, want ErrConnClosed carrying IdleTimeoutError", err)
	}
	if cause := closeCause(t, c); !errors.As(cause, &idle) {
		t.Fatalf("cause = %v, want IdleTimeoutError", cause)
	}
}

// TestSendKeepaliveSendsPing checks that SendKeepalive puts one empty PING
// on the connection stream, and that an inbound PING leaves the connection
// unchanged and draws no reply.
func TestSendKeepaliveSendsPing(t *testing.T) {
	c, p := newRawPeer(t, Server, 0)
	p.sync(t) // an inbound PING
	if err := c.SendKeepalive(); err != nil {
		t.Fatal(err)
	}
	if f := p.expect(t, typePing, 0); len(f.payload) != 0 {
		t.Fatalf("PING carries %d payload bytes", len(f.payload))
	}
	requireOpen(t, c)
}
