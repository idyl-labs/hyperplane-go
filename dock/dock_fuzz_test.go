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

package dock

import (
	"bytes"
	"context"
	"io"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire"
	commonpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

// dock_fuzz_test.go: fuzz targets for every place the dock reads bytes
// the edge controls: the first byte and attribution header of an inbound
// bidirectional stream (and the RPC preface behind it), the control
// stream, and pushed event frames. Each target checks the outcome against
// the documented contract, not only the absence of a panic.

// bytesStream is a transportStream that serves fixed bytes and then EOF,
// and records cancels. It never blocks, so the dispatch functions can be
// driven synchronously.
type bytesStream struct {
	r           *bytes.Reader
	cancelRead  []uint64
	cancelWrite []uint64
}

func newBytesStream(b []byte) *bytesStream { return &bytesStream{r: bytes.NewReader(b)} }

func (s *bytesStream) Read(p []byte) (int, error)      { return s.r.Read(p) }
func (s *bytesStream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *bytesStream) Close() error                    { return nil }
func (s *bytesStream) CancelRead(code uint64)          { s.cancelRead = append(s.cancelRead, code) }
func (s *bytesStream) CancelWrite(code uint64)         { s.cancelWrite = append(s.cancelWrite, code) }
func (s *bytesStream) SetReadDeadline(time.Time) error { return nil }

// refusedWithProtocol reports whether both directions were reset exactly
// once with DockCodeProtocol.
func (s *bytesStream) refusedWithProtocol() bool {
	return slices.Equal(s.cancelRead, []uint64{wire.DockCodeProtocol}) &&
		slices.Equal(s.cancelWrite, []uint64{wire.DockCodeProtocol})
}

func (s *bytesStream) untouched() bool { return len(s.cancelRead) == 0 && len(s.cancelWrite) == 0 }

func mustFrame(tb testing.TB, m proto.Message) []byte {
	tb.Helper()
	var b bytes.Buffer
	if err := wire.WriteFrame(&b, m); err != nil {
		tb.Fatalf("frame: %v", err)
	}
	return b.Bytes()
}

func mustLaneHeader(tb testing.TB, h wire.LaneStreamHeader) []byte {
	tb.Helper()
	b, err := wire.AppendLaneHeader(nil, h)
	if err != nil {
		tb.Fatalf("lane header: %v", err)
	}
	return b
}

// FuzzInboundStreamDispatch feeds arbitrary bytes as an edge-opened
// bidirectional stream to a dock that has lane 1 live and lane 2 ended.
// The contract: a stream beginning with StreamKindLane and a well-formed
// header naming lane 1 is delivered to that lane with the decoded class
// and header, which re-encode to the bytes read, and its payload is the
// rest of the stream byte for byte; a stream beginning with 0x00 reaches
// AcceptRPC, which either returns the RpcOpen metadata and the remaining
// bytes or refuses; everything else is refused in both directions with
// DockCodeProtocol. Every outcome returns or keeps exactly the backlog
// slots the contract says.
func FuzzInboundStreamDispatch(f *testing.F) {
	f.Add(append(mustLaneHeader(f, wire.LaneStreamHeader{LaneID: 1, Class: wire.LaneStreamClassPassthrough, Header: []byte("pod-a")}), "payload"...))
	f.Add(mustLaneHeader(f, wire.LaneStreamHeader{LaneID: 1, Class: wire.LaneStreamClassE2EMTLS}))
	f.Add(mustLaneHeader(f, wire.LaneStreamHeader{LaneID: 2, Class: wire.LaneStreamClassPassthrough}))
	f.Add(mustLaneHeader(f, wire.LaneStreamHeader{LaneID: 1 << 40, Class: wire.LaneStreamClassPassthrough}))
	f.Add([]byte{wire.StreamKindLane, 0x81, 0x00, 0x02, 0x00, 0x00}) // non-minimal varint
	f.Add([]byte{wire.StreamKindLane, 0x01, 0x02, 0x00, 0x05, 'a'})  // header shorter than declared
	f.Add(append(mustFrame(f, &dpb.RpcOpen{Metadata: []byte(ReportRPCMetadata)}), "body"...))
	f.Add([]byte{0x00, 0x00, 0x00, 0x0a})
	f.Add([]byte{0x7f})
	f.Add([]byte{})

	restore := swapLaneAttachWait(0) // an unknown lane is refused at once
	f.Cleanup(restore)

	f.Fuzz(func(t *testing.T, raw []byte) {
		conn := newLaneConn()
		defer conn.cancel()
		d := &Dock{conn: conn, transport: wire.TransportQUIC, drained: make(chan struct{})}
		d.laneAttached(&dockpb.LaneAttached{LaneId: 1, LaneClass: wire.LaneClassStream})
		d.laneAttached(&dockpb.LaneAttached{LaneId: 2, LaneClass: wire.LaneClassStream})
		d.laneClosed(&dockpb.LaneClosed{LaneId: 2, Cause: dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED})
		set := d.laneset()
		lane := set.lanes[1]

		s := newBytesStream(raw)
		set.sem <- struct{}{}
		d.routeStream(set, s)

		switch {
		case len(raw) > 0 && raw[0] == wire.StreamKindLane:
			hr := bytes.NewReader(raw[1:])
			h, err := wire.ReadLaneHeader(hr)
			if err != nil || h.LaneID != 1 {
				if !s.refusedWithProtocol() || len(lane.streams) != 0 || len(set.sem) != 0 {
					t.Fatalf("lane stream (header err %v, lane %d) not refused: cancels %v/%v, queued %d, slots %d",
						err, h.LaneID, s.cancelRead, s.cancelWrite, len(lane.streams), len(set.sem))
				}
				return
			}
			headerLen := len(raw) - hr.Len()
			if len(lane.streams) != 1 || !s.untouched() || len(set.sem) != 1 {
				t.Fatalf("valid lane stream: queued %d, cancels %v/%v, slots %d", len(lane.streams), s.cancelRead, s.cancelWrite, len(set.sem))
			}
			ls := lane.streams[0]
			if ls.Class() != h.Class || !bytes.Equal(ls.Header(), h.Header) || len(ls.Header()) > wire.LaneHeaderMaxLen {
				t.Fatalf("delivered class %#x header %q, decoded %#x %q", ls.Class(), ls.Header(), h.Class, h.Header)
			}
			if re := mustLaneHeader(t, h); !bytes.Equal(re, raw[:headerLen]) {
				t.Fatalf("header re-encodes to %x, read %x", re, raw[:headerLen])
			}
			payload, err := io.ReadAll(ls)
			if err != nil || !bytes.Equal(payload, raw[headerLen:]) {
				t.Fatalf("payload %x, %v; want %x", payload, err, raw[headerLen:])
			}
		case len(raw) > 0 && raw[0] == 0x00:
			if len(set.rpc) != 1 || !s.untouched() || len(set.sem) != 0 {
				t.Fatalf("RPC stream: queued %d, cancels %v/%v, slots %d", len(set.rpc), s.cancelRead, s.cancelWrite, len(set.sem))
			}
			want := bytes.NewReader(raw)
			var open dpb.RpcOpen
			wantErr := wire.ReadFrame(want, &open, 0)
			md, rpc, err := d.AcceptRPC(context.Background())
			if (err != nil) != (wantErr != nil) {
				t.Fatalf("AcceptRPC error %v, codec error %v", err, wantErr)
			}
			if err != nil {
				if !s.refusedWithProtocol() {
					t.Fatalf("malformed RPC preface not refused: cancels %v/%v", s.cancelRead, s.cancelWrite)
				}
				return
			}
			if !bytes.Equal(md, open.GetMetadata()) {
				t.Fatalf("metadata %q, want %q", md, open.GetMetadata())
			}
			rest, _ := io.ReadAll(want)
			body, err := io.ReadAll(rpc)
			if err != nil || !bytes.Equal(body, rest) {
				t.Fatalf("RPC body %x, %v; want %x", body, err, rest)
			}
		default:
			if !s.refusedWithProtocol() || len(set.sem) != 0 || len(set.rpc) != 0 {
				t.Fatalf("stream with kind %x not refused: cancels %v/%v", raw[:min(len(raw), 1)], s.cancelRead, s.cancelWrite)
			}
		}
	})
}

// controlModel is the documented control-stream semantics, applied to
// decoded frames: drain is a one-way latch; LaneAttached admits a nonzero
// id that is neither live nor ended; LaneClosed ends an id once, live or
// not, for the life of the connection.
type controlModel struct {
	drained bool
	live    map[uint64]*dockpb.LaneAttached
	dead    map[uint64]dockpb.LaneCloseCause
	pending []uint64
}

func (m *controlModel) apply(e2c *dockpb.EdgeToClient) {
	switch {
	case e2c.GetDrain() != nil:
		m.drained = true
	case e2c.GetLaneAttached() != nil:
		la := e2c.GetLaneAttached()
		id := la.GetLaneId()
		_, live := m.live[id]
		_, dead := m.dead[id]
		if id != 0 && !live && !dead {
			m.live[id] = la
			m.pending = append(m.pending, id)
		}
	case e2c.GetLaneClosed() != nil:
		lc := e2c.GetLaneClosed()
		if _, dead := m.dead[lc.GetLaneId()]; !dead {
			m.dead[lc.GetLaneId()] = lc.GetCause()
			delete(m.live, lc.GetLaneId())
		}
	}
}

// FuzzControlStream feeds arbitrary bytes to the control-stream watcher
// and compares the dock's drain latch and lane registry with the model
// built from the same frames: the watcher stops at the first frame it
// cannot decode, never panics, and never resurrects an ended lane.
func FuzzControlStream(f *testing.F) {
	attach := func(id uint64) []byte {
		return mustFrame(f, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{LaneAttached: &dockpb.LaneAttached{
			LaneId: id, PeerPrincipal: "spiffe://example.com/node-a", LaneClass: wire.LaneClassStream, Metadata: []byte("m"),
		}}})
	}
	closeLane := func(id uint64) []byte {
		return mustFrame(f, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneClosed{LaneClosed: &dockpb.LaneClosed{
			LaneId: id, Cause: dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED,
		}}})
	}
	drain := mustFrame(f, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Drain{Drain: &dockpb.DockDrain{}}})
	welcomeFrame := mustFrame(f, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Welcome{Welcome: &dockpb.DockWelcome{
		Gen: &commonpb.DockGen{Slot: 1}, KeepaliveMs: 1,
	}}})
	overloaded := mustFrame(f, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Overloaded{Overloaded: &dockpb.DockOverloaded{RetryAfterMs: 1}}})

	f.Add(slices.Concat(attach(1), attach(2), closeLane(1), drain))
	f.Add(slices.Concat(attach(1), closeLane(1), attach(1), attach(0), closeLane(0), attach(0)))
	f.Add(slices.Concat(closeLane(5), attach(5), drain, drain))
	f.Add(slices.Concat(welcomeFrame, overloaded, attach(3)))
	f.Add(slices.Concat(attach(7), []byte{0x00, 0x00, 0x00, 0x03, 0xff, 0xff, 0xff}, attach(8)))
	f.Add([]byte{0x00, 0x20, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, raw []byte) {
		d := &Dock{conn: newLaneConn(), control: newBytesStream(raw), drained: make(chan struct{})}
		d.watchControl() // returns at the first frame it cannot read

		m := controlModel{live: map[uint64]*dockpb.LaneAttached{}, dead: map[uint64]dockpb.LaneCloseCause{}}
		r := bytes.NewReader(raw)
		for {
			var e2c dockpb.EdgeToClient
			if wire.ReadFrame(r, &e2c, 0) != nil {
				break
			}
			m.apply(&e2c)
		}

		select {
		case <-d.Drained():
			if !m.drained {
				t.Fatal("Drained closed without a drain frame")
			}
		default:
			if m.drained {
				t.Fatal("drain frame did not close Drained")
			}
		}
		set := d.laneset()
		if len(set.lanes) != len(m.live) || len(set.dead) != len(m.dead) || len(set.pending) != len(m.pending) {
			t.Fatalf("registry live %d dead %d pending %d; model %d %d %d",
				len(set.lanes), len(set.dead), len(set.pending), len(m.live), len(m.dead), len(m.pending))
		}
		for id, cause := range m.dead {
			if got, ok := set.dead[id]; !ok || got != cause {
				t.Fatalf("lane %d ended with %v (recorded %v), model %v", id, got, ok, cause)
			}
		}
		for i, l := range set.pending {
			if l.ID() != m.pending[i] {
				t.Fatalf("pending[%d] = lane %d, model lane %d", i, l.ID(), m.pending[i])
			}
			cause, ended := m.dead[l.ID()]
			select {
			case <-l.Closed():
				if !ended || l.CloseCause() != cause {
					t.Fatalf("lane %d closed with %v; model ended %v cause %v", l.ID(), l.CloseCause(), ended, cause)
				}
			default:
				if ended {
					t.Fatalf("lane %d ended in the model but Closed has not fired", l.ID())
				}
				la := m.live[l.ID()]
				if set.lanes[l.ID()] != l || l.Classes() != la.GetLaneClass() || l.PeerPrincipal() != la.GetPeerPrincipal() ||
					!bytes.Equal(l.Metadata(), la.GetMetadata()) {
					t.Fatalf("lane %d attributes differ from its LaneAttached", l.ID())
				}
			}
		}
	})
}

// FuzzEventPush feeds arbitrary bytes as a pushed event stream. The
// contract: a stream whose first frame decodes as an EventPush yields
// exactly that payload and is read to its end rather than reset; any
// other stream is refused with an error and its read side is reset with
// DockCodeProtocol.
func FuzzEventPush(f *testing.F) {
	f.Add(mustFrame(f, &dpb.EventPush{Payload: []byte("event-a")}))
	f.Add(append(mustFrame(f, &dpb.EventPush{Payload: []byte("event-b")}), "trailing"...))
	f.Add(mustFrame(f, &dpb.EventPush{}))
	f.Add([]byte{0x00, 0x20, 0x00, 0x00})
	f.Add([]byte{0x00, 0x00, 0x00, 0x02, 0x0a})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, raw []byte) {
		d, conn := newEventDock(t)
		s := newBytesStream(raw)
		conn.unis <- s

		var want dpb.EventPush
		wantErr := wire.ReadFrame(bytes.NewReader(raw), &want, 0)
		payload, err := d.AcceptEvent(context.Background())
		if (err != nil) != (wantErr != nil) {
			t.Fatalf("AcceptEvent error %v, codec error %v", err, wantErr)
		}
		if err != nil {
			if !slices.Equal(s.cancelRead, []uint64{wire.DockCodeProtocol}) {
				t.Fatalf("refused event stream read cancels %v, want one DockCodeProtocol", s.cancelRead)
			}
			return
		}
		if !bytes.Equal(payload, want.GetPayload()) || len(payload) > wire.DefaultMaxFrame {
			t.Fatalf("payload %x, want %x", payload, want.GetPayload())
		}
		if !s.untouched() || s.r.Len() != 0 {
			t.Fatalf("accepted event stream: cancels %v, %d bytes left unread", s.cancelRead, s.r.Len())
		}
	})
}
