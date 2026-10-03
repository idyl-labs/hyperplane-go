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
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

// flow_test.go: lane flows against a fake edge. The fake edge injects raw
// datagram bytes built by hand from the grammar, never by this package's
// own encoder, so every drop case demonstrates its mechanism against a
// positive control in the same setup.

// flowConn is the transportConn fake with the QUIC datagram plane: client
// sends land on sent, and the test injects edge-to-client datagrams on
// inbound.
type flowConn struct {
	*laneConn
	sent    chan []byte
	inbound chan []byte
}

func newFlowConn() *flowConn {
	return &flowConn{
		laneConn: newLaneConn(),
		sent:     make(chan []byte, 256),
		inbound:  make(chan []byte, 256),
	}
}

func (c *flowConn) SendDatagram(b []byte) error {
	select {
	case c.sent <- b:
		return nil
	default:
		return errors.New("test: sent buffer full")
	}
}

func (c *flowConn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	select {
	case b := <-c.inbound:
		return b, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

// newFlowDock builds a QUIC dock over the datagram-capable fake, with its
// control watcher running.
func newFlowDock(t *testing.T) (*Dock, *laneEdge, *flowConn) {
	t.Helper()
	ctrlEdge, ctrlClient := newLanePipe()
	fc := newFlowConn()
	d := &Dock{
		conn:      fc,
		transport: wire.TransportQUIC,
		control:   ctrlClient,
		drained:   make(chan struct{}),
	}
	go d.watchControl()
	t.Cleanup(func() {
		fc.cancel()
		_ = ctrlEdge.Close()
	})
	return d, &laneEdge{t: t, conn: fc.laneConn, control: ctrlEdge}, fc
}

// attachLane sends one LaneAttached and claims the lane with AcceptLane.
func attachLane(t *testing.T, d *Dock, e *laneEdge, id, classes uint64) *Lane {
	t.Helper()
	e.attach(id, classes, "spiffe://example.com/peer", nil)
	l, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane(%d): %v", id, err)
	}
	if l.ID() != id {
		t.Fatalf("AcceptLane returned lane %d, want %d", l.ID(), id)
	}
	return l
}

// endLane closes lane l at the edge and waits until the dock observes it.
func endLane(t *testing.T, e *laneEdge, l *Lane, cause dockpb.LaneCloseCause) {
	t.Helper()
	e.closeLane(l.ID(), cause)
	select {
	case <-l.Closed():
	case <-time.After(5 * time.Second):
		t.Fatalf("LaneClosed for lane %d not observed", l.ID())
	}
}

// dgram hand-builds a flow datagram for single-byte ids from the grammar:
// lane id | flow id | payload.
func dgram(laneID, flowID byte, payload string) []byte {
	return append([]byte{laneID, flowID}, payload...)
}

// queuedFlows reports how many flow items lane l holds.
func queuedFlows(d *Dock, l *Lane) int {
	set := d.laneset()
	set.mu.Lock()
	defer set.mu.Unlock()
	return len(l.flows)
}

// waitFlowQueue waits until lane l holds want queued flow items, for
// cases that must observe the queue itself.
func waitFlowQueue(t *testing.T, d *Dock, l *Lane, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		n := queuedFlows(d, l)
		if n == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("flow queue = %d, want %d", n, want)
		}
		time.Sleep(time.Millisecond)
	}
}

// shortCtx is a short wait for cases that assert that nothing arrives.
func shortCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	t.Cleanup(cancel)
	return ctx
}

// SendFlow emits exactly the attribution prefix, a minimal varint lane id
// and a minimal varint flow id, then the payload. It is checked against
// the standard library's varint encoder and against a hand-built literal,
// across multi-byte ids and the boundary flow ids: 0 and the maximum are
// valid, because only lane id 0 is reserved.
func TestSendFlowFramesDatagram(t *testing.T) {
	d, e, fc := newFlowDock(t)
	for _, laneID := range []uint64{7, 128, 1 << 32} {
		l := attachLane(t, d, e, laneID, wire.LaneClassStream|wire.LaneClassFlow)
		for _, flowID := range []uint64{0, 1, 300, 1<<64 - 1} {
			payload := []byte("pay")
			if err := l.SendFlow(flowID, payload); err != nil {
				t.Fatalf("SendFlow(lane %d, flow %d): %v", laneID, flowID, err)
			}
			want := binary.AppendUvarint(binary.AppendUvarint(nil, laneID), flowID)
			want = append(want, payload...)
			select {
			case got := <-fc.sent:
				if !bytes.Equal(got, want) {
					t.Fatalf("SendFlow(lane %d, flow %d) sent %x, want %x", laneID, flowID, got, want)
				}
			default:
				t.Fatalf("SendFlow(lane %d, flow %d) sent nothing", laneID, flowID)
			}
		}
	}

	// A literal, so that the reference encoder and this package cannot
	// share one bug: lane 9, flow 300 is 0x09 0xAC 0x02.
	l := attachLane(t, d, e, 9, wire.LaneClassFlow)
	if err := l.SendFlow(300, []byte("x")); err != nil {
		t.Fatalf("SendFlow literal: %v", err)
	}
	if got := <-fc.sent; !bytes.Equal(got, []byte{0x09, 0xAC, 0x02, 'x'}) {
		t.Fatalf("SendFlow literal sent %x, want 09ac0278", got)
	}
}

// A lane not granted the flow class refuses SendFlow and ReceiveFlow
// locally with ErrFlowClassNotGranted and sends no datagram; an ended
// lane refuses SendFlow with ErrLaneClosed. Positive control: a flow lane
// on the same dock sends.
func TestSendFlowRefusedLocally(t *testing.T) {
	d, e, fc := newFlowDock(t)

	streamOnly := attachLane(t, d, e, 3, wire.LaneClassStream)
	if err := streamOnly.SendFlow(1, []byte("p")); !errors.Is(err, ErrFlowClassNotGranted) {
		t.Fatalf("SendFlow on a stream-only lane: %v, want ErrFlowClassNotGranted", err)
	}
	if _, _, err := streamOnly.ReceiveFlow(laneCtx(t)); !errors.Is(err, ErrFlowClassNotGranted) {
		t.Fatalf("ReceiveFlow on a stream-only lane: %v, want ErrFlowClassNotGranted", err)
	}
	select {
	case b := <-fc.sent:
		t.Fatalf("a local refusal still sent %x", b)
	default:
	}

	ended := attachLane(t, d, e, 4, wire.LaneClassFlow)
	endLane(t, e, ended, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED)
	if err := ended.SendFlow(1, []byte("p")); !errors.Is(err, ErrLaneClosed) {
		t.Fatalf("SendFlow on an ended lane: %v, want ErrLaneClosed", err)
	}

	live := attachLane(t, d, e, 5, wire.LaneClassFlow)
	if err := live.SendFlow(1, []byte("p")); err != nil {
		t.Fatalf("positive control SendFlow: %v", err)
	}
	if got := <-fc.sent; !bytes.Equal(got, []byte{0x05, 0x01, 'p'}) {
		t.Fatalf("positive control sent %x", got)
	}
}

// A lane granted the flow class on a connection without a datagram plane
// is refused like an ungranted lane: such a grant breaks the edge's
// contract, and the dock fails closed rather than claiming a send.
func TestSendFlowWithoutDatagramPlaneRefused(t *testing.T) {
	d, e := newLaneDock(t) // laneConn has no datagram plane
	l := attachLane(t, d, e, 5, wire.LaneClassFlow)
	if err := l.SendFlow(1, []byte("p")); !errors.Is(err, ErrFlowClassNotGranted) {
		t.Fatalf("SendFlow without a datagram plane: %v, want ErrFlowClassNotGranted", err)
	}
}

// Inbound datagrams are attributed by the dock's own lane id, and the flow
// id and payload surface unchanged. Another lane on the same dock sees
// none of them, and delivery keeps arrival order.
func TestReceiveFlowAttributesByLane(t *testing.T) {
	d, e, fc := newFlowDock(t)
	l5 := attachLane(t, d, e, 5, wire.LaneClassFlow)
	l9 := attachLane(t, d, e, 9, wire.LaneClassFlow)

	// A multi-byte flow id (1<<40): lane 0x05, then the reference varint,
	// then the payload.
	big := binary.AppendUvarint([]byte{0x05}, 1<<40)
	fc.inbound <- append(big, "first"...)
	fc.inbound <- dgram(5, 2, "second")

	flowID, payload, err := l5.ReceiveFlow(laneCtx(t))
	if err != nil || flowID != 1<<40 || !bytes.Equal(payload, []byte("first")) {
		t.Fatalf("ReceiveFlow #1 = (%d, %q, %v), want (1<<40, \"first\")", flowID, payload, err)
	}
	flowID, payload, err = l5.ReceiveFlow(laneCtx(t))
	if err != nil || flowID != 2 || !bytes.Equal(payload, []byte("second")) {
		t.Fatalf("ReceiveFlow #2 = (%d, %q, %v), want (2, \"second\")", flowID, payload, err)
	}

	if _, _, err := l9.ReceiveFlow(shortCtx(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lane 9 ReceiveFlow = %v, want a deadline (no item for another lane)", err)
	}
}

// Keepalives are discarded as transport activity, and malformed
// attribution, unknown or ended lanes and flow items for a lane without
// the flow class are dropped without notice. The pump survives every one
// of them: a positive control sent last is delivered.
func TestReceiveFlowSilentDrops(t *testing.T) {
	d, e, fc := newFlowDock(t)
	live := attachLane(t, d, e, 5, wire.LaneClassFlow)
	streamOnly := attachLane(t, d, e, 3, wire.LaneClassStream)
	dead := attachLane(t, d, e, 8, wire.LaneClassFlow)
	endLane(t, e, dead, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED)

	drops := [][]byte{
		{0x00},                  // the keepalive: activity only
		{0x00, 0xFF, 0x07},      // leading varint 0, then junk: never parsed further
		{0x85, 0x00, 0x07, 'x'}, // a non-minimal encoding of live lane 5: malformed, not attributed
		{0x05},                  // truncated: no flow id
		{0x63, 0x01, 'x'},       // lane 99, never attached
		dgram(8, 1, "x"),        // an ended lane stays ended
		dgram(3, 1, "x"),        // a lane without the flow class
	}
	for _, b := range drops {
		fc.inbound <- b
	}
	// The pump processes datagrams in order, so delivery of the control
	// proves every drop above was consumed.
	fc.inbound <- dgram(5, 7, "alive")

	flowID, payload, err := live.ReceiveFlow(laneCtx(t))
	if err != nil || flowID != 7 || !bytes.Equal(payload, []byte("alive")) {
		t.Fatalf("positive control = (%d, %q, %v), want (7, \"alive\")", flowID, payload, err)
	}
	if nLive, nStream := queuedFlows(d, live), queuedFlows(d, streamOnly); nLive != 0 || nStream != 0 {
		t.Fatalf("queues after the drops: live=%d streamOnly=%d, want 0/0", nLive, nStream)
	}
}

// An ended lane drops its queued flow items with it, and ReceiveFlow
// returns ErrLaneClosed.
func TestReceiveFlowDroppedAtLaneClose(t *testing.T) {
	d, e, fc := newFlowDock(t)
	l := attachLane(t, d, e, 5, wire.LaneClassFlow)

	fc.inbound <- dgram(5, 1, "queued")
	waitFlowQueue(t, d, l, 1)

	endLane(t, e, l, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_LEG_UNDOCK)
	if _, _, err := l.ReceiveFlow(laneCtx(t)); !errors.Is(err, ErrLaneClosed) {
		t.Fatalf("ReceiveFlow after close = %v, want ErrLaneClosed", err)
	}
	if n := queuedFlows(d, l); n != 0 {
		t.Fatalf("%d queued flow items survived the close", n)
	}
}

// The per-lane queue holds at most flowBacklog items and drops the oldest
// first, so a slow consumer keeps the newest flowBacklog items.
func TestReceiveFlowBacklogDropsOldest(t *testing.T) {
	d, e, fc := newFlowDock(t)
	l := attachLane(t, d, e, 5, wire.LaneClassFlow)
	// ReceiveFlow starts the pump; nothing is consumed yet.
	if _, _, err := l.ReceiveFlow(shortCtx(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("priming ReceiveFlow = %v, want a deadline", err)
	}

	const extra = 3
	for i := 0; i < flowBacklog+extra; i++ {
		b := binary.AppendUvarint([]byte{0x05}, uint64(i))
		fc.inbound <- append(b, "p"...)
	}
	waitFlowQueue(t, d, l, flowBacklog)

	for i := 0; i < flowBacklog; i++ {
		flowID, _, err := l.ReceiveFlow(laneCtx(t))
		if err != nil {
			t.Fatalf("drain #%d: %v", i, err)
		}
		if want := uint64(extra + i); flowID != want {
			t.Fatalf("drain #%d = flow %d, want %d (the oldest %d dropped first)", i, flowID, want, extra)
		}
	}
	if _, _, err := l.ReceiveFlow(shortCtx(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ReceiveFlow after the drain = %v, want a deadline (exactly flowBacklog kept)", err)
	}
}

// ReceiveFlow returns when its context is canceled and when the dock ends.
func TestReceiveFlowReturnsOnCancelAndDockEnd(t *testing.T) {
	d, e, fc := newFlowDock(t)
	l := attachLane(t, d, e, 5, wire.LaneClassFlow)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := l.ReceiveFlow(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReceiveFlow with a canceled context = %v, want context.Canceled", err)
	}

	fc.cancel()
	if _, _, err := l.ReceiveFlow(laneCtx(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("ReceiveFlow on an ended dock = %v, want the connection's context.Canceled", err)
	}
}

// The datagram plane is QUIC-only by type: the fallback connection does
// not provide it, because the fallback has no datagram frame type, and the
// QUIC connection does.
func TestFallbackTransportHasNoDatagramPlane(t *testing.T) {
	var fb transportConn = &fallbackTransportConn{}
	if _, ok := fb.(transportDatagramConn); ok {
		t.Fatal("fallbackTransportConn provides a datagram plane; the fallback has no datagram frame type")
	}
	var q transportConn = quicTransportConn{}
	if _, ok := q.(transportDatagramConn); !ok {
		t.Fatal("quicTransportConn must provide the datagram plane")
	}
}
