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
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

// dock_accept_test.go: the receiving surface (AcceptEvent, AcceptRPC,
// AcceptLane, Lane.AcceptStream and Lane.OpenStream) against the fake
// edge in lane_test.go: every way an accept ends (a value, the caller's
// context, the dock's end) and every refusal of an inbound stream.

// eventConn extends the lane fake with edge-opened unidirectional
// streams, the carrier of pushed events.
type eventConn struct {
	*laneConn
	unis chan transportReceiveStream
}

func (c *eventConn) AcceptUniStream(ctx context.Context) (transportReceiveStream, error) {
	select {
	case s := <-c.unis:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

// newEventDock builds a dock over eventConn. It has no control watcher:
// the event path does not use the control stream.
func newEventDock(t *testing.T) (*Dock, *eventConn) {
	t.Helper()
	conn := &eventConn{laneConn: newLaneConn(), unis: make(chan transportReceiveStream, 4)}
	t.Cleanup(conn.cancel)
	return &Dock{conn: conn, transport: wire.TransportQUIC, drained: make(chan struct{})}, conn
}

// pushEvent opens an edge-initiated unidirectional stream and writes raw
// on it from a goroutine (net.Pipe writes block until read). When fin is
// set, the edge then closes its end, which the dock reads as EOF.
func pushEvent(c *eventConn, raw []byte, fin bool) *lanePipeStream {
	edge, s := newLanePipe()
	c.unis <- s
	go func() {
		_, _ = edge.Write(raw)
		if fin {
			_ = edge.Close()
		}
	}()
	return s
}

func eventFrame(tb testing.TB, payload []byte) []byte {
	tb.Helper()
	var b bytes.Buffer
	if err := wire.WriteFrame(&b, &dpb.EventPush{Payload: payload}); err != nil {
		tb.Fatalf("event frame: %v", err)
	}
	return b.Bytes()
}

// AcceptEvent returns the pushed payload and then reads the stream to the
// edge's FIN instead of resetting it: a reset on the success path could
// discard the edge's final bytes, and an unread stream would hold one
// unit of the dock's incoming stream credit forever.
func TestAcceptEventReturnsPayloadAndDrainsToFIN(t *testing.T) {
	d, conn := newEventDock(t)
	s := pushEvent(conn, eventFrame(t, []byte("event-a")), true)

	payload, err := d.AcceptEvent(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptEvent: %v", err)
	}
	if string(payload) != "event-a" {
		t.Fatalf("payload = %q, want event-a", payload)
	}
	s.notCanceled(t)
}

// A peer that never sends FIN cannot hold an event stream open: the drain
// after the payload is bounded by drainTimeout, after which the stream is
// reset. The payload is still delivered, because it was complete.
func TestAcceptEventResetsStreamWhenFINNeverArrives(t *testing.T) {
	old := drainTimeout
	drainTimeout = 20 * time.Millisecond
	t.Cleanup(func() { drainTimeout = old })

	d, conn := newEventDock(t)
	s := pushEvent(conn, eventFrame(t, []byte("event-b")), false)

	payload, err := d.AcceptEvent(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptEvent: %v", err)
	}
	if string(payload) != "event-b" {
		t.Fatalf("payload = %q, want event-b", payload)
	}
	s.mu.Lock()
	reads := append([]uint64(nil), s.cancelRead...)
	s.mu.Unlock()
	if len(reads) != 1 || reads[0] != wire.DockCodeProtocol {
		t.Fatalf("read side cancels = %v, want one DockCodeProtocol reset after the bounded drain", reads)
	}
}

// A malformed event frame is refused with the frame codec's error class
// and the stream's read side is reset, so a bad push never strands
// stream credit.
func TestAcceptEventRefusesOversizedFrame(t *testing.T) {
	d, conn := newEventDock(t)
	// Declared length 2 MiB: one byte past nothing, far past the 1 MiB cap.
	s := pushEvent(conn, []byte{0x00, 0x20, 0x00, 0x00}, false)

	if _, err := d.AcceptEvent(laneCtx(t)); !errors.Is(err, wire.ErrFrameTooLarge) {
		t.Fatalf("AcceptEvent = %v, want ErrFrameTooLarge", err)
	}
	s.mu.Lock()
	reads := append([]uint64(nil), s.cancelRead...)
	s.mu.Unlock()
	if len(reads) != 1 || reads[0] != wire.DockCodeProtocol {
		t.Fatalf("read side cancels = %v, want one DockCodeProtocol reset", reads)
	}
}

// AcceptEvent ends with the caller's context, and with the dock: the two
// are told apart by their causes.
func TestAcceptEventEndsWithContextOrDock(t *testing.T) {
	d, conn := newEventDock(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.AcceptEvent(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptEvent with an expired context = %v, want DeadlineExceeded", err)
	}
	conn.cancel()
	if _, err := d.AcceptEvent(laneCtx(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("AcceptEvent on an ended dock = %v, want the dock's end", err)
	}
}

// openRPCStream opens an edge-initiated RPC stream and writes its RpcOpen
// frame followed by body from a goroutine, returning both ends.
func openRPCStream(e *laneEdge, metadata, body []byte) openedStream {
	e.t.Helper()
	var frame bytes.Buffer
	if err := wire.WriteFrame(&frame, &dpb.RpcOpen{Metadata: metadata}); err != nil {
		e.t.Fatalf("rpc frame: %v", err)
	}
	return e.openRaw(append(frame.Bytes(), body...))
}

// An accepted RPC is a bidirectional byte pipe: the opener's bytes after
// the RpcOpen frame read through, replies write through, and Close
// half-closes the dock's side so the opener reads EOF.
func TestAcceptRPCIsABidirectionalPipe(t *testing.T) {
	d, e := newLaneDock(t)
	o := openRPCStream(e, []byte(ReportRPCMetadata), []byte("ping"))

	md, rpc, err := d.AcceptRPC(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptRPC: %v", err)
	}
	if string(md) != ReportRPCMetadata {
		t.Fatalf("metadata = %q, want %q", md, ReportRPCMetadata)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(rpc, got); err != nil || string(got) != "ping" {
		t.Fatalf("RPC read = %q, %v; want ping", got, err)
	}
	wrote := make(chan error, 1)
	go func() {
		_, err := rpc.Write([]byte("pong"))
		if err == nil {
			err = rpc.Close()
		}
		wrote <- err
	}()
	reply, err := io.ReadAll(o.edge)
	if err != nil || string(reply) != "pong" {
		t.Fatalf("opener read = %q, %v; want pong then EOF", reply, err)
	}
	if err := <-wrote; err != nil {
		t.Fatalf("RPC write/close: %v", err)
	}
	o.s.notCanceled(t)
}

// The caller's context bounds AcceptRPC; with nothing queued, a dock that
// has ended reports its end rather than blocking.
func TestAcceptRPCEndsWithContextOrDock(t *testing.T) {
	d, e := newLaneDock(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := d.AcceptRPC(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptRPC with an expired context = %v, want DeadlineExceeded", err)
	}
	e.conn.cancel()
	if _, _, err := d.AcceptRPC(laneCtx(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("AcceptRPC on an ended dock = %v, want the dock's end", err)
	}
}

// waitFor polls cond, a white-box view of queue state that has no event
// to wait on, under a generous bound.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

// RPC streams that were routed before the dock ended stay claimable after
// it ends, as AcceptRPC documents; a stream that could not be queued
// because the backlog was full is refused with DockCodeProtocol when the
// dock ends, rather than held forever.
func TestAcceptRPCAfterDockEndDrainsQueueAndRefusesOverflow(t *testing.T) {
	d, e := newLaneDock(t)
	set := d.laneset()
	d.ensurePump()

	total := acceptBacklog + 1
	opened := make([]openedStream, total)
	for i := range opened {
		opened[i] = openRPCStream(e, []byte("rpc"), nil)
	}
	// The RPC queue is full, and the one extra stream holds its backlog slot
	// while it waits to be queued (the pump holds the other).
	waitFor(t, "a full RPC queue with one overflow stream", func() bool {
		return len(set.rpc) == acceptBacklog && len(set.sem) == 2 && len(e.conn.accepts) == 0
	})

	e.conn.cancel()

	refused := make(chan int, total)
	for i, o := range opened {
		go func() {
			<-o.s.canceled
			refused <- i
		}()
	}
	var overflow int
	select {
	case overflow = <-refused:
	case <-time.After(5 * time.Second):
		t.Fatal("the overflow RPC stream was not refused when the dock ended")
	}
	opened[overflow].s.waitCanceled(t, wire.DockCodeProtocol)

	for i := 0; i < acceptBacklog; i++ {
		md, rpc, err := d.AcceptRPC(laneCtx(t))
		if err != nil {
			t.Fatalf("queued RPC %d not claimable after the dock ended: %v", i, err)
		}
		if string(md) != "rpc" {
			t.Fatalf("queued RPC %d metadata = %q", i, md)
		}
		rpc.Abort()
	}
	if _, _, err := d.AcceptRPC(laneCtx(t)); err == nil {
		t.Fatal("AcceptRPC returned an RPC after the queue was drained on an ended dock")
	}
}

// AcceptLane ends with the caller's context and with the dock, and the
// two causes stay distinct.
func TestAcceptLaneEndsWithContextOrDock(t *testing.T) {
	d, e := newLaneDock(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := d.AcceptLane(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptLane with an expired context = %v, want DeadlineExceeded", err)
	}
	e.conn.cancel()
	if _, err := d.AcceptLane(laneCtx(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("AcceptLane on an ended dock = %v, want the dock's end", err)
	}
}

// Lane.AcceptStream ends with the caller's context and with the dock
// while the lane itself is still live.
func TestLaneAcceptStreamEndsWithContextOrDock(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(3, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := lane.AcceptStream(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptStream with an expired context = %v, want DeadlineExceeded", err)
	}
	e.conn.cancel()
	if _, err := lane.AcceptStream(laneCtx(t)); !errors.Is(err, context.Canceled) {
		t.Fatalf("AcceptStream on an ended dock = %v, want the dock's end", err)
	}
}

// The registry admits each lane id once per connection: lane id 0 is
// never valid, a repeated LaneAttached for a live id is a duplicate, and
// an id that has ended is never attached again. Frames are applied in
// stream order, so a sentinel lane surfacing proves every earlier frame
// was processed.
func TestLaneAttachedAdmitsEachLaneIDOnce(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(0, wire.LaneClassStream, "", nil)               // invalid id
	e.attach(7, wire.LaneClassStream, "node-a", []byte("1")) // admitted
	e.attach(7, wire.LaneClassFlow, "node-b", []byte("2"))   // duplicate of a live lane
	e.closeLane(8, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED)
	e.attach(8, wire.LaneClassStream, "", nil) // id already ended
	e.attach(9, wire.LaneClassStream, "", nil) // sentinel

	var got []uint64
	for len(got) < 2 {
		l, err := d.AcceptLane(laneCtx(t))
		if err != nil {
			t.Fatalf("AcceptLane after %v: %v", got, err)
		}
		got = append(got, l.ID())
		if l.ID() == 7 && (l.PeerPrincipal() != "node-a" || string(l.Metadata()) != "1") {
			t.Fatalf("duplicate LaneAttached replaced lane 7: peer %q metadata %q", l.PeerPrincipal(), l.Metadata())
		}
	}
	if got[0] != 7 || got[1] != 9 {
		t.Fatalf("lanes surfaced %v, want [7 9]", got)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if l, err := d.AcceptLane(ctx); err == nil {
		t.Fatalf("an extra lane %d surfaced", l.ID())
	}
}

// A repeated drain request is idempotent: Drained stays closed and the
// control watcher keeps applying later frames.
func TestRepeatedDrainKeepsControlStreamServing(t *testing.T) {
	d, e := newLaneDock(t)
	e.drain()
	e.drain()
	e.attach(4, wire.LaneClassStream, "", nil)
	if _, err := d.AcceptLane(laneCtx(t)); err != nil {
		t.Fatalf("control stream stopped after a repeated drain: %v", err)
	}
	select {
	case <-d.Drained():
	default:
		t.Fatal("Drained is not closed after a drain request")
	}
}

// An inbound stream that ends before its first byte has no kind and is
// refused in both directions with DockCodeProtocol; dispatch keeps
// serving the next stream.
func TestInboundStreamEndingBeforeKindIsRefused(t *testing.T) {
	d, e := newLaneDock(t)
	edge, s := newLanePipe()
	e.conn.accepts <- s
	_ = edge.Close()
	d.ensurePump()
	s.waitCanceled(t, wire.DockCodeProtocol)

	e.openRPC([]byte("next"))
	md, rpc, err := d.AcceptRPC(laneCtx(t))
	if err != nil || string(md) != "next" {
		t.Fatalf("AcceptRPC after a refused stream: %q, %v", md, err)
	}
	rpc.Abort()
}

// A stream held for a lane not yet attached is released as soon as the
// dock ends, without waiting out laneAttachWait: a held stream never
// outlives its connection.
func TestHeldLaneStreamRefusedWhenDockEnds(t *testing.T) {
	d, e := newLaneDock(t)
	d.ensurePump()
	o := e.openRaw(laneAttr(42, wire.LaneStreamClassPassthrough, ""))
	set := d.laneset()
	waitFor(t, "the stream to be held for lane 42", func() bool {
		set.mu.Lock()
		defer set.mu.Unlock()
		return set.parked[42] > 0
	})

	start := time.Now()
	e.conn.cancel()
	o.s.waitCanceled(t, wire.DockCodeProtocol)
	if waited := time.Since(start); waited >= laneAttachWait {
		t.Fatalf("held stream released after %s, not at the dock's end", waited)
	}
}

// failOpenConn is a lane fake whose stream opens fail or return a stream
// that cannot be written.
type failOpenConn struct {
	*laneConn
	openErr   error
	brokenOut *lanePipeStream
}

func (c *failOpenConn) OpenStreamSync(context.Context) (transportStream, error) {
	if c.openErr != nil {
		return nil, c.openErr
	}
	return c.brokenOut, nil
}

// newDockOver builds a dock over conn with a control watcher, attaches
// lane id and returns the accepted lane.
func newDockOver(t *testing.T, conn transportConn, lc *laneConn, id uint64) *Lane {
	t.Helper()
	ctrlEdge, ctrlClient := newLanePipe()
	d := &Dock{conn: conn, transport: wire.TransportQUIC, control: ctrlClient, drained: make(chan struct{})}
	go d.watchControl()
	t.Cleanup(func() {
		lc.cancel()
		_ = ctrlEdge.Close()
	})
	e := &laneEdge{t: t, conn: lc, control: ctrlEdge}
	e.attach(id, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}
	return lane
}

// OpenStream encodes the attribution header before it opens a stream, so
// a class or header with no legal wire form is refused with the codec's
// error class and costs no stream.
func TestLaneOpenStreamRefusesUnencodableHeaderWithoutOpening(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(2, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}
	cases := map[string]struct {
		class byte
		hdr   []byte
	}{
		"class 0x00":            {0x00, nil},
		"unassigned class 0x03": {0x03, nil},
		"header one past bound": {wire.LaneStreamClassPassthrough, make([]byte, wire.LaneHeaderMaxLen+1)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := lane.OpenStream(laneCtx(t), tc.class, tc.hdr); !errors.Is(err, wire.ErrLaneAttribution) {
				t.Fatalf("OpenStream = %v, want ErrLaneAttribution", err)
			}
		})
	}
	if n := e.conn.opens.Load(); n != 0 {
		t.Fatalf("%d streams opened for unencodable headers, want 0", n)
	}
	// Positive control: the bound itself encodes.
	o := make(chan openedStream, 1)
	go func() { o <- <-e.conn.opened }()
	go func() {
		s, err := lane.OpenStream(laneCtx(t), wire.LaneStreamClassPassthrough, make([]byte, wire.LaneHeaderMaxLen))
		if err == nil {
			s.Abort()
		}
	}()
	opened := <-o
	h, err := readKindAndHeader(opened.edge)
	if err != nil || len(h.Header) != wire.LaneHeaderMaxLen {
		t.Fatalf("header at the bound: %d bytes, %v", len(h.Header), err)
	}
}

// readKindAndHeader reads a lane stream's kind byte and attribution
// header from the edge end.
func readKindAndHeader(r io.Reader) (wire.LaneStreamHeader, error) {
	var kind [1]byte
	if _, err := io.ReadFull(r, kind[:]); err != nil {
		return wire.LaneStreamHeader{}, err
	}
	if kind[0] != wire.StreamKindLane {
		return wire.LaneStreamHeader{}, errors.New("not a lane stream")
	}
	return wire.ReadLaneHeader(r)
}

// A transport that cannot open a stream surfaces its own error from
// OpenStream unchanged.
func TestLaneOpenStreamSurfacesTransportOpenError(t *testing.T) {
	errOpen := errors.New("open refused")
	lc := newLaneConn()
	lane := newDockOver(t, &failOpenConn{laneConn: lc, openErr: errOpen}, lc, 6)
	if _, err := lane.OpenStream(laneCtx(t), wire.LaneStreamClassPassthrough, nil); !errors.Is(err, errOpen) {
		t.Fatalf("OpenStream = %v, want the transport's open error", err)
	}
}

// A stream whose attribution header cannot be written is reset in both
// directions with DockCodeProtocol and never returned: a half-attributed
// stream would be a protocol violation at the edge.
func TestLaneOpenStreamResetsStreamWhenHeaderWriteFails(t *testing.T) {
	edge, s := newLanePipe()
	_ = edge.Close() // writes to s now fail
	lc := newLaneConn()
	lane := newDockOver(t, &failOpenConn{laneConn: lc, brokenOut: s}, lc, 6)
	got, err := lane.OpenStream(laneCtx(t), wire.LaneStreamClassPassthrough, []byte("hdr"))
	if err == nil || got != nil {
		t.Fatalf("OpenStream = %v, %v; want an error and no stream", got, err)
	}
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("OpenStream error = %v, want the write error", err)
	}
	s.waitCanceled(t, wire.DockCodeProtocol)
}

// Abort resets both directions of one lane stream with DockCodeProtocol
// and leaves the lane live: the next stream on it still opens.
func TestLaneStreamAbortResetsOnlyThatStream(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(2, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}
	openOne := func() (*LaneStream, openedStream) {
		t.Helper()
		type result struct {
			s   *LaneStream
			err error
		}
		res := make(chan result, 1)
		go func() {
			s, err := lane.OpenStream(laneCtx(t), wire.LaneStreamClassE2EMTLS, []byte("h"))
			res <- result{s, err}
		}()
		o := <-e.conn.opened
		if _, err := readKindAndHeader(o.edge); err != nil {
			t.Fatalf("attribution: %v", err)
		}
		r := <-res
		if r.err != nil {
			t.Fatalf("OpenStream: %v", r.err)
		}
		return r.s, o
	}
	first, firstEdge := openOne()
	if first.Lane() != lane || first.Class() != wire.LaneStreamClassE2EMTLS || string(first.Header()) != "h" {
		t.Fatalf("stream attribution = lane %d class %#x header %q", first.Lane().ID(), first.Class(), first.Header())
	}
	first.Abort()
	firstEdge.s.waitCanceled(t, wire.DockCodeProtocol)
	select {
	case <-lane.Closed():
		t.Fatal("aborting one stream ended the lane")
	default:
	}
	second, secondEdge := openOne()
	second.Abort()
	secondEdge.s.waitCanceled(t, wire.DockCodeProtocol)
}

// NewRPCConn passes bytes through to the RPC unchanged and reports the
// placeholder addresses and no-op deadlines it documents, so a stream
// protocol layered on it sees an ordinary net.Conn.
func TestNewRPCConnPassesBytesThroughAndReportsPlaceholders(t *testing.T) {
	d, e := newLaneDock(t)
	o := openRPCStream(e, nil, []byte("in"))
	_, rpc, err := d.AcceptRPC(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptRPC: %v", err)
	}
	c := NewRPCConn(rpc, nil)
	got := make([]byte, 2)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "in" {
		t.Fatalf("conn read = %q, %v", got, err)
	}
	wrote := make(chan error, 1)
	go func() { _, err := c.Write([]byte("out")); wrote <- err }()
	reply := make([]byte, 3)
	if _, err := io.ReadFull(o.edge, reply); err != nil || string(reply) != "out" {
		t.Fatalf("opener read = %q, %v", reply, err)
	}
	if err := <-wrote; err != nil {
		t.Fatalf("conn write: %v", err)
	}
	for _, a := range []net.Addr{c.LocalAddr(), c.RemoteAddr()} {
		if a.Network() != "hyperplane-rpc" || a.String() != "hyperplane-rpc" {
			t.Fatalf("address = %s/%s, want the hyperplane-rpc placeholder", a.Network(), a.String())
		}
	}
	now := time.Now()
	if c.SetDeadline(now) != nil || c.SetReadDeadline(now) != nil || c.SetWriteDeadline(now) != nil {
		t.Fatal("deadline setters must be no-ops that return nil")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	o.s.waitCanceled(t, wire.DockCodeProtocol)
}
