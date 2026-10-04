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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

// lane_test.go: the lane surface against a fake edge. The fake edge
// writes raw bytes (control frames via wire.WriteFrame on the control
// pipe, and stream attribution headers built by hand from the grammar), so
// every refusal case demonstrates its mechanism against a positive control
// in the same setup rather than replaying this package's own encoder.

// laneAttr hand-builds a lane stream attribution header from the grammar:
// 0x03 | LEB128 lane_id (minimal) | class | u16 hdr_len BE | hdr. Only
// single-byte lane_ids are needed here; multi-byte forms are covered by
// the wire codec tests.
func laneAttr(laneID byte, class byte, hdr string) []byte {
	b := []byte{0x03, laneID, class, byte(len(hdr) >> 8), byte(len(hdr))}
	return append(b, hdr...)
}

// swapLaneAttachWait shrinks the bound on holding a stream for a lane not
// yet attached, and returns a function that restores it.
func swapLaneAttachWait(d time.Duration) func() {
	old := laneAttachWait
	laneAttachWait = d
	return func() { laneAttachWait = old }
}

// lanePipeStream is one end of a net.Pipe as a transportStream,
// recording Close and cancels. The first cancel closes the pipe so
// blocked reads on either end return, as a transport reset would.
type lanePipeStream struct {
	c net.Conn

	mu          sync.Mutex
	closed      bool
	cancelRead  []uint64
	cancelWrite []uint64

	canceled  chan struct{}
	cancelOne sync.Once
}

func newLanePipe() (edge net.Conn, s *lanePipeStream) {
	a, b := net.Pipe()
	return a, &lanePipeStream{c: b, canceled: make(chan struct{})}
}

func (s *lanePipeStream) Read(p []byte) (int, error)  { return s.c.Read(p) }
func (s *lanePipeStream) Write(p []byte) (int, error) { return s.c.Write(p) }

func (s *lanePipeStream) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return s.c.Close()
}

func (s *lanePipeStream) CancelRead(code uint64) {
	s.mu.Lock()
	s.cancelRead = append(s.cancelRead, code)
	s.mu.Unlock()
	s.cancelOne.Do(func() { close(s.canceled); _ = s.c.Close() })
}

func (s *lanePipeStream) CancelWrite(code uint64) {
	s.mu.Lock()
	s.cancelWrite = append(s.cancelWrite, code)
	s.mu.Unlock()
	s.cancelOne.Do(func() { close(s.canceled); _ = s.c.Close() })
}

func (s *lanePipeStream) SetReadDeadline(t time.Time) error { return s.c.SetReadDeadline(t) }

// waitCanceled asserts both directions were reset with code: a refused
// stream is always canceled both ways.
func (s *lanePipeStream) waitCanceled(t *testing.T, code uint64) {
	t.Helper()
	select {
	case <-s.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("stream was not canceled")
	}
	// Both halves are canceled back to back; poll the second briefly.
	deadline := time.Now().Add(2 * time.Second)
	for {
		s.mu.Lock()
		r, w := len(s.cancelRead), len(s.cancelWrite)
		okCode := (r == 0 || s.cancelRead[0] == code) && (w == 0 || s.cancelWrite[0] == code)
		s.mu.Unlock()
		if r > 0 && w > 0 {
			if !okCode {
				t.Fatalf("cancel codes read=%v write=%v, want %#x", s.cancelRead, s.cancelWrite, code)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cancelRead=%d cancelWrite=%d, want both directions reset", r, w)
		}
		time.Sleep(time.Millisecond)
	}
}

// notCanceled asserts the stream survived (the positive-control side of
// a refusal case).
func (s *lanePipeStream) notCanceled(t *testing.T) {
	t.Helper()
	select {
	case <-s.canceled:
		s.mu.Lock()
		defer s.mu.Unlock()
		t.Fatalf("stream canceled: read=%v write=%v", s.cancelRead, s.cancelWrite)
	default:
	}
}

// openedStream hands a test both ends of a client-opened stream.
type openedStream struct {
	edge net.Conn
	s    *lanePipeStream
}

// laneConn is the transportConn fake: edge-opened streams flow through
// accepts; client opens hand their edge end back on opened.
type laneConn struct {
	ctx     context.Context
	cancel  context.CancelFunc
	accepts chan transportStream
	opened  chan openedStream
	opens   atomic.Int32
}

func newLaneConn() *laneConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &laneConn{
		ctx: ctx, cancel: cancel,
		// Room past acceptBacklog: tests that fill the backlog park the
		// overflow here instead of blocking the test goroutine.
		accepts: make(chan transportStream, 2*acceptBacklog),
		opened:  make(chan openedStream, 16),
	}
}

func (c *laneConn) OpenStreamSync(context.Context) (transportStream, error) {
	c.opens.Add(1)
	edge, s := newLanePipe()
	c.opened <- openedStream{edge: edge, s: s}
	return s, nil
}

func (c *laneConn) AcceptStream(ctx context.Context) (transportStream, error) {
	select {
	case s := <-c.accepts:
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

func (c *laneConn) AcceptUniStream(ctx context.Context) (transportReceiveStream, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	}
}

func (c *laneConn) SendKeepalive() error                { return nil }
func (c *laneConn) CloseWithError(uint64, string) error { c.cancel(); return nil }
func (c *laneConn) Context() context.Context            { return c.ctx }
func (c *laneConn) Resumed() bool                       { return false }

// laneEdge drives the fake edge's half of the wire.
type laneEdge struct {
	t       *testing.T
	conn    *laneConn
	control net.Conn
}

// newLaneDock builds a dock over the fakes with its control watcher
// running, on the QUIC transport.
func newLaneDock(t *testing.T) (*Dock, *laneEdge) {
	t.Helper()
	return newLaneDockOn(t, wire.TransportQUIC)
}

// newLaneDockOn is newLaneDock on the named transport.
func newLaneDockOn(t *testing.T, transport string) (*Dock, *laneEdge) {
	t.Helper()
	ctrlEdge, ctrlClient := newLanePipe()
	conn := newLaneConn()
	d := &Dock{
		conn:      conn,
		transport: transport,
		control:   ctrlClient,
		drained:   make(chan struct{}),
	}
	go d.watchControl()
	t.Cleanup(func() {
		conn.cancel()
		_ = ctrlEdge.Close()
	})
	return d, &laneEdge{t: t, conn: conn, control: ctrlEdge}
}

func (e *laneEdge) attach(id, classes uint64, peer string, metadata []byte) {
	e.t.Helper()
	if err := wire.WriteFrame(e.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{
		LaneAttached: &dockpb.LaneAttached{LaneId: id, PeerPrincipal: peer, LaneClass: classes, Metadata: metadata},
	}}); err != nil {
		e.t.Fatalf("attach frame: %v", err)
	}
}

func (e *laneEdge) closeLane(id uint64, cause dockpb.LaneCloseCause) {
	e.t.Helper()
	if err := wire.WriteFrame(e.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneClosed{
		LaneClosed: &dockpb.LaneClosed{LaneId: id, Cause: cause},
	}}); err != nil {
		e.t.Fatalf("close frame: %v", err)
	}
}

func (e *laneEdge) drain() {
	e.t.Helper()
	if err := wire.WriteFrame(e.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Drain{
		Drain: &dockpb.DockDrain{},
	}}); err != nil {
		e.t.Fatalf("drain frame: %v", err)
	}
}

// openRaw opens an edge-initiated bidi stream carrying exactly b, then
// keeps the edge end open for payload exchange.
func (e *laneEdge) openRaw(b []byte) openedStream {
	e.t.Helper()
	edge, s := newLanePipe()
	e.conn.accepts <- s
	go func() {
		if len(b) > 0 {
			_, _ = edge.Write(b)
		}
	}()
	return openedStream{edge: edge, s: s}
}

// openRPC opens an edge-initiated bidi stream carrying one RpcOpen frame:
// a length-prefixed protobuf with no kind byte. The frame size cap keeps
// the high byte of the four-byte length zero, so the stream leads 0x00.
func (e *laneEdge) openRPC(metadata []byte) {
	e.t.Helper()
	edge, s := newLanePipe()
	e.conn.accepts <- s
	go func() {
		_ = wire.WriteFrame(edge, &dpb.RpcOpen{Metadata: metadata})
	}()
}

func laneCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestLaneAttachedSurfacesLane: a control-stream LaneAttached surfaces
// the lane with its granted classes, advisory peer principal, and opaque
// metadata; the lane is live, not closed.
func TestLaneAttachedSurfacesLane(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(7, wire.LaneClassStream|wire.LaneClassFlow, "spiffe://td/workload", []byte("meta"))

	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}
	if lane.ID() != 7 {
		t.Errorf("ID = %d, want 7", lane.ID())
	}
	if lane.Classes() != wire.LaneClassStream|wire.LaneClassFlow {
		t.Errorf("Classes = %#x, want stream|flow", lane.Classes())
	}
	if lane.PeerPrincipal() != "spiffe://td/workload" {
		t.Errorf("PeerPrincipal = %q", lane.PeerPrincipal())
	}
	if !bytes.Equal(lane.Metadata(), []byte("meta")) {
		t.Errorf("Metadata = %q, want %q", lane.Metadata(), "meta")
	}
	select {
	case <-lane.Closed():
		t.Fatal("fresh lane reports closed")
	default:
	}
}

// TestLaneClosedSignalsOnce: LaneClosed fires Closed with its cause; a
// duplicate LaneClosed and one for an unknown lane_id are no-ops, since
// LaneClosed is an idempotent notification; and the control watcher keeps
// serving drain afterwards (positive control in the same setup).
func TestLaneClosedSignalsOnce(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(7, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	e.closeLane(7, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_LEG_UNDOCK)
	select {
	case <-lane.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("Closed did not fire")
	}
	if got := lane.CloseCause(); got != dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_LEG_UNDOCK {
		t.Fatalf("CloseCause = %v, want LEG_UNDOCK", got)
	}

	// Duplicate for the same lane and a close for a lane never attached:
	// both no-ops.
	e.closeLane(7, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED)
	e.closeLane(99, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_EXPIRY)

	// Positive control: the watcher is still consuming the control
	// stream, so drain lands (and, being ordered after the duplicates,
	// synchronizes the cause assertion below).
	e.drain()
	select {
	case <-d.Drained():
	case <-time.After(5 * time.Second):
		t.Fatal("drain did not land after lane frames")
	}
	if got := lane.CloseCause(); got != dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_LEG_UNDOCK {
		t.Fatalf("duplicate LaneClosed replaced the cause: %v", got)
	}
}

// TestAcceptDispatchRoutesRPCAndLane: inbound bidi streams route by
// first byte (0x00-led delivery frames to AcceptRPC, kind byte 0x03 to
// the named lane), each keeping its byte pipe.
func TestAcceptDispatchRoutesRPCAndLane(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(5, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	e.openRPC([]byte("rpc-meta"))
	raw := e.openRaw(append(laneAttr(5, wire.LaneStreamClassPassthrough, "hdr"), "ping"...))

	md, rpc, err := d.AcceptRPC(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptRPC: %v", err)
	}
	if !bytes.Equal(md, []byte("rpc-meta")) {
		t.Errorf("rpc metadata = %q", md)
	}
	defer rpc.Abort()

	ls, err := lane.AcceptStream(laneCtx(t))
	if err != nil {
		t.Fatalf("Lane.AcceptStream: %v", err)
	}
	if ls.Lane() != lane || ls.Class() != wire.LaneStreamClassPassthrough || !bytes.Equal(ls.Header(), []byte("hdr")) {
		t.Fatalf("attribution: lane=%v class=%#x header=%q", ls.Lane() == lane, ls.Class(), ls.Header())
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(ls, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("payload after header: %q, %v", buf, err)
	}
	go func() { _, _ = ls.Write([]byte("pong")) }()
	back := make([]byte, 4)
	if _, err := io.ReadFull(raw.edge, back); err != nil || string(back) != "pong" {
		t.Fatalf("return payload: %q, %v", back, err)
	}
}

// TestAcceptDispatchRefusesUnknownKind: a first byte that is neither a
// delivery frame's 0x00 nor StreamKindLane has no assigned protocol, so
// the stream is reset both ways with DockCodeProtocol, while a
// well-formed lane stream in the same setup is delivered.
func TestAcceptDispatchRefusesUnknownKind(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(6, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	bad := e.openRaw([]byte{0x07, 'j', 'u', 'n', 'k'})
	bad.s.waitCanceled(t, wire.DockCodeProtocol)

	good := e.openRaw(laneAttr(6, wire.LaneStreamClassE2EMTLS, ""))
	ls, err := lane.AcceptStream(laneCtx(t))
	if err != nil {
		t.Fatalf("positive control not delivered: %v", err)
	}
	good.s.notCanceled(t)
	ls.Abort()
}

// TestAcceptStreamHeldUntilAttachDelivered: the edge writes LaneAttached
// before opening the paired stream, but QUIC gives no cross-stream
// delivery order, so a stream naming a lane_id not yet seen is held while
// control frames catch up, then delivered.
func TestAcceptStreamHeldUntilAttachDelivered(t *testing.T) {
	d, e := newLaneDock(t)

	// Stream first. AcceptLane is not yet listening for lane 9; prime
	// dispatch via a goroutine accepting on the dock.
	raw := e.openRaw(append(laneAttr(9, wire.LaneStreamClassE2EMTLS, "h"), "x"...))
	laneCh := make(chan *Lane, 1)
	go func() {
		lane, err := d.AcceptLane(laneCtx(t))
		if err == nil {
			laneCh <- lane
		}
	}()

	// The dispatch must be holding the stream, not refusing it: wait for
	// the parked marker, then deliver the attach.
	deadline := time.Now().Add(5 * time.Second)
	for {
		set := d.laneset()
		set.mu.Lock()
		parked := set.parked[9]
		set.mu.Unlock()
		if parked > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("stream for a not-yet-attached lane was never held for control catch-up")
		}
		time.Sleep(time.Millisecond)
	}
	raw.s.notCanceled(t)

	e.attach(9, wire.LaneClassStream, "", nil)
	lane := <-laneCh
	ls, err := lane.AcceptStream(laneCtx(t))
	if err != nil {
		t.Fatalf("held stream not delivered after attach: %v", err)
	}
	if ls.Lane().ID() != 9 || !bytes.Equal(ls.Header(), []byte("h")) {
		t.Fatalf("attribution: id=%d header=%q", ls.Lane().ID(), ls.Header())
	}
	buf := make([]byte, 1)
	if _, err := io.ReadFull(ls, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("payload: %q, %v", buf, err)
	}
}

// TestAcceptStreamUnknownLaneBounded: the hold is bounded. A stream
// naming a lane_id that no control frame ever announces is a protocol
// violation (a foreign lane_id is refused with DockCodeProtocol). The
// same setup's attached lane keeps receiving streams.
func TestAcceptStreamUnknownLaneBounded(t *testing.T) {
	defer swapLaneAttachWait(50 * time.Millisecond)()
	d, e := newLaneDock(t)
	e.attach(4, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	foreign := e.openRaw(laneAttr(3, wire.LaneStreamClassE2EMTLS, ""))
	foreign.s.waitCanceled(t, wire.DockCodeProtocol)

	good := e.openRaw(laneAttr(4, wire.LaneStreamClassE2EMTLS, ""))
	ls, err := lane.AcceptStream(laneCtx(t))
	if err != nil {
		t.Fatalf("positive control not delivered: %v", err)
	}
	good.s.notCanceled(t)
	ls.Abort()
}

// TestAcceptStreamMalformedAttribution: a malformed attribution header (a
// non-minimal varint, lane_id 0, an unassigned stream class, or a header
// that ends mid-grammar) is reset both ways with DockCodeProtocol; a
// well-formed stream in the same setup is delivered.
func TestAcceptStreamMalformedAttribution(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(5, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	cases := []struct {
		name  string
		bytes []byte
	}{
		{"non-minimal varint", []byte{0x03, 0x85, 0x00, 0x01, 0x00, 0x00}},
		{"lane_id zero", []byte{0x03, 0x00, 0x01, 0x00, 0x00}},
		{"unassigned stream class", []byte{0x03, 0x05, 0x00, 0x00, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := e.openRaw(tc.bytes)
			s.s.waitCanceled(t, wire.DockCodeProtocol)
		})
	}
	t.Run("header ends mid-grammar", func(t *testing.T) {
		s := e.openRaw(nil)
		_, _ = s.edge.Write([]byte{0x03, 0x05}) // then FIN before the class byte
		_ = s.edge.Close()
		s.s.waitCanceled(t, wire.DockCodeProtocol)
	})

	t.Run("positive control", func(t *testing.T) {
		s := e.openRaw(laneAttr(5, wire.LaneStreamClassE2EMTLS, ""))
		if _, err := lane.AcceptStream(laneCtx(t)); err != nil {
			t.Fatalf("well-formed stream not delivered: %v", err)
		}
		s.s.notCanceled(t)
	})
}

// TestAcceptStreamDeadLaneRefused: a closed lane_id stays dead (an edge
// never reuses one), so a stream naming a closed lane is refused like a
// foreign one, while a live lane in the same setup still receives.
func TestAcceptStreamDeadLaneRefused(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(4, wire.LaneClassStream, "", nil)
	dead, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}
	e.closeLane(4, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_LEG_UNDOCK)
	select {
	case <-dead.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("Closed did not fire")
	}
	e.attach(6, wire.LaneClassStream, "", nil)
	live, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	s := e.openRaw(laneAttr(4, wire.LaneStreamClassE2EMTLS, ""))
	s.s.waitCanceled(t, wire.DockCodeProtocol)

	good := e.openRaw(laneAttr(6, wire.LaneStreamClassE2EMTLS, ""))
	ls, err := live.AcceptStream(laneCtx(t))
	if err != nil {
		t.Fatalf("live lane stream not delivered: %v", err)
	}
	good.s.notCanceled(t)
	ls.Abort()
}

// TestLaneOpenStreamWritesAttributionThenPipes: Lane.OpenStream leads
// with the exact attribution bytes, then is a transparent pipe; Close
// sends FIN, which the peer reads as EOF, and the clean path never
// resets the stream.
func TestLaneOpenStreamWritesAttributionThenPipes(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(8, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	type opened struct {
		ls  *LaneStream
		err error
	}
	done := make(chan opened, 1)
	go func() {
		ls, err := lane.OpenStream(laneCtx(t), wire.LaneStreamClassE2EMTLS, []byte("h"))
		done <- opened{ls, err}
	}()
	os := <-e.conn.opened

	want := laneAttr(8, wire.LaneStreamClassE2EMTLS, "h") // built from the grammar, not by the encoder
	got := make([]byte, len(want))
	if _, err := io.ReadFull(os.edge, got); err != nil {
		t.Fatalf("attribution read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("attribution = % x, want % x", got, want)
	}
	op := <-done
	if op.err != nil {
		t.Fatalf("OpenStream: %v", op.err)
	}

	go func() { _, _ = op.ls.Write([]byte("data")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(os.edge, buf); err != nil || string(buf) != "data" {
		t.Fatalf("payload: %q, %v", buf, err)
	}
	go func() { _, _ = os.edge.Write([]byte("resp")) }()
	if _, err := io.ReadFull(op.ls, buf); err != nil || string(buf) != "resp" {
		t.Fatalf("response: %q, %v", buf, err)
	}

	if err := op.ls.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.edge.Read(buf); err == nil {
		t.Fatal("peer did not observe FIN")
	}
	op.ls.stream.(*lanePipeStream).notCanceled(t)
}

// TestLaneOpenStreamAfterCloseRefusedLocally: a lane never resurrects
// and a closed lane_id has no addressable peer state, so after
// LaneClosed, OpenStream refuses locally with ErrLaneClosed and opens
// nothing. The same lane opened streams before it ended (positive
// control), and Abort resets both directions of one.
func TestLaneOpenStreamAfterCloseRefusedLocally(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(8, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	done := make(chan *LaneStream, 1)
	go func() {
		ls, err := lane.OpenStream(laneCtx(t), wire.LaneStreamClassPassthrough, nil)
		if err != nil {
			t.Errorf("OpenStream before close: %v", err)
		}
		done <- ls
	}()
	os := <-e.conn.opened
	go func() { _, _ = io.Copy(io.Discard, os.edge) }()
	ls := <-done
	before := d.conn.(*laneConn).opens.Load()

	ls.Abort()
	os.s.waitCanceled(t, wire.DockCodeProtocol)

	e.closeLane(8, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_POLICY_REVOKED)
	select {
	case <-lane.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("Closed did not fire")
	}
	if _, err := lane.OpenStream(laneCtx(t), wire.LaneStreamClassPassthrough, nil); !errors.Is(err, ErrLaneClosed) {
		t.Fatalf("OpenStream on ended lane: %v, want ErrLaneClosed", err)
	}
	if got := d.conn.(*laneConn).opens.Load(); got != before {
		t.Fatalf("OpenStream on ended lane still opened a stream (%d → %d)", before, got)
	}
}

// queuedUnclaimed reads a lane's delivered-but-unclaimed stream count
// (white-box, under the registry lock).
func queuedUnclaimed(d *Dock, l *Lane) int {
	set := d.laneset()
	set.mu.Lock()
	defer set.mu.Unlock()
	return len(l.streams)
}

// TestAcceptBacklogBoundsUnclaimedLaneStreams: the fixed accept backlog
// (the same bound the fallback mux applies to stream opens) bounds
// streams accepted ahead of their consumer. Delivered-but-unclaimed lane
// streams count against it: delivery plateaus at acceptBacklog until a
// consumer claims, and each claim admits exactly the next stream (the
// positive control for the same mechanism).
func TestAcceptBacklogBoundsUnclaimedLaneStreams(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(5, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	total := acceptBacklog + 6
	for i := 0; i < total; i++ {
		e.openRaw(laneAttr(5, wire.LaneStreamClassPassthrough, ""))
	}

	deadline := time.Now().Add(5 * time.Second)
	for queuedUnclaimed(d, lane) < acceptBacklog {
		if time.Now().After(deadline) {
			t.Fatalf("only %d streams delivered, want the backlog filled (%d)", queuedUnclaimed(d, lane), acceptBacklog)
		}
		time.Sleep(time.Millisecond)
	}
	// Settle: with no consumer, delivery must hold exactly at the bound.
	time.Sleep(100 * time.Millisecond)
	if got := queuedUnclaimed(d, lane); got != acceptBacklog {
		t.Fatalf("%d unclaimed streams delivered, want the accept backlog to hold at %d", got, acceptBacklog)
	}

	// Claiming one stream admits exactly the next: the count returns to
	// the bound and no further.
	if _, err := lane.AcceptStream(laneCtx(t)); err != nil {
		t.Fatalf("AcceptStream: %v", err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for queuedUnclaimed(d, lane) < acceptBacklog {
		if time.Now().After(deadline) {
			t.Fatal("claiming a stream did not admit the next accepted stream")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if got := queuedUnclaimed(d, lane); got != acceptBacklog {
		t.Fatalf("%d unclaimed streams after one claim, want %d", got, acceptBacklog)
	}
}

// TestLaneCloseReleasesUnclaimedStreams: a lane's end tears down its
// streams. Delivered-but-unclaimed streams are reset with code 0, a
// teardown code that receivers ignore, and their backlog slots return, so
// the dock keeps accepting. AcceptStream after the end reports
// ErrLaneClosed.
func TestLaneCloseReleasesUnclaimedStreams(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(5, wire.LaneClassStream, "", nil)
	lane, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatalf("AcceptLane: %v", err)
	}

	opened := make([]openedStream, 0, acceptBacklog)
	for i := 0; i < acceptBacklog; i++ {
		opened = append(opened, e.openRaw(laneAttr(5, wire.LaneStreamClassPassthrough, "")))
	}
	deadline := time.Now().Add(5 * time.Second)
	for queuedUnclaimed(d, lane) < acceptBacklog {
		if time.Now().After(deadline) {
			t.Fatalf("only %d streams delivered, want %d", queuedUnclaimed(d, lane), acceptBacklog)
		}
		time.Sleep(time.Millisecond)
	}

	e.closeLane(5, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_LEG_UNDOCK)
	select {
	case <-lane.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("Closed did not fire")
	}

	if _, err := lane.AcceptStream(laneCtx(t)); !errors.Is(err, ErrLaneClosed) {
		t.Fatalf("AcceptStream after the lane ended: %v, want ErrLaneClosed", err)
	}
	// The queued streams were torn with the lane: reset code 0.
	opened[0].s.waitCanceled(t, 0)

	// Positive control: the slots returned, so a fresh delivery frame
	// stream still routes to AcceptRPC.
	e.openRPC([]byte("after-close"))
	md, rpc, err := d.AcceptRPC(laneCtx(t))
	if err != nil || string(md) != "after-close" {
		t.Fatalf("AcceptRPC after slot release: %q, %v", md, err)
	}
	rpc.Abort()
}
