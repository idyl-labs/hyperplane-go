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
	"sync"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/generation"
	"github.com/idyl-labs/hyperplane-go/wire"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

// requester_test.go: the delivery verbs a dock sends (SendEvent, OpenRPC
// and OpenLane) against scripted edge replies. Every path checks what
// happens to the one-shot delivery stream: a stream that is never released
// would hold one unit of the edge's stream credit forever.

// rpcConn returns a single scripted stream from OpenStreamSync; the rest
// of the transportConn surface is unused by the delivery verbs.
type rpcConn struct{ s transportStream }

func (c *rpcConn) OpenStreamSync(context.Context) (transportStream, error) { return c.s, nil }
func (c *rpcConn) AcceptStream(context.Context) (transportStream, error)   { panic("not used") }
func (c *rpcConn) AcceptUniStream(context.Context) (transportReceiveStream, error) {
	panic("not used")
}
func (c *rpcConn) SendKeepalive() error                { panic("not used") }
func (c *rpcConn) CloseWithError(uint64, string) error { panic("not used") }
func (c *rpcConn) Context() context.Context            { return context.Background() }
func (c *rpcConn) Resumed() bool                       { return false }
func (c *rpcConn) ExportKeyingMaterial(string, []byte, int) ([]byte, error) {
	panic("not used")
}

func edgeReplyFrame(tb testing.TB, msg *dpb.EdgeToRequester) []byte {
	tb.Helper()
	var buf bytes.Buffer
	if err := wire.WriteFrame(&buf, msg); err != nil {
		tb.Fatal(err)
	}
	return buf.Bytes()
}

func ackReply() *dpb.EdgeToRequester {
	return &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Ack{Ack: &dpb.Ack{}}}
}

// A refused OpenRPC releases the stream it opened. A Nak is an ordinary
// outcome, so a leak here would cost one stream per refusal.
func TestOpenRPCReleasesStreamOnNak(t *testing.T) {
	reply := edgeReplyFrame(t, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Nak{
		Nak: &dpb.Nak{Code: dpb.NakCode_NAK_CODE_LOCATOR_INVALID},
	}})
	s := &recordingStream{serve: bytes.NewReader(reply), err: io.EOF}
	d := &Dock{conn: &rpcConn{s: s}}

	_, err := d.OpenRPC(context.Background(), []byte("loc"), nil)
	var nak NakError
	if !errors.As(err, &nak) || nak.Code != dpb.NakCode_NAK_CODE_LOCATOR_INVALID {
		t.Fatalf("OpenRPC error = %v, want NakError NAK_CODE_LOCATOR_INVALID", err)
	}
	if !s.released() {
		t.Fatal("OpenRPC leaked the stream on a Nak")
	}
}

// A reply OpenRPC cannot use is a failure too, and releases the stream.
func TestOpenRPCReleasesStreamOnUnexpectedReply(t *testing.T) {
	reply := edgeReplyFrame(t, &dpb.EdgeToRequester{}) // no reply arm set
	s := &recordingStream{serve: bytes.NewReader(reply), err: io.EOF}
	d := &Dock{conn: &rpcConn{s: s}}

	if _, err := d.OpenRPC(context.Background(), []byte("loc"), nil); err == nil {
		t.Fatal("OpenRPC with an unexpected reply succeeded")
	}
	if !s.released() {
		t.Fatal("OpenRPC leaked the stream on an unexpected reply")
	}
}

// A confirmed OpenRPC hands the stream to the returned RPC, so nothing
// releases it.
func TestOpenRPCKeepsStreamOnSuccess(t *testing.T) {
	reply := edgeReplyFrame(t, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_RpcOpened{
		RpcOpened: &dpb.RpcOpened{},
	}})
	s := &recordingStream{serve: bytes.NewReader(reply), err: io.EOF}
	d := &Dock{conn: &rpcConn{s: s}}

	rpc, err := d.OpenRPC(context.Background(), []byte("loc"), nil)
	if err != nil || rpc == nil {
		t.Fatalf("OpenRPC = %v, %v", rpc, err)
	}
	if s.released() {
		t.Fatal("OpenRPC released the stream it handed to the RPC")
	}
}

// blockingDrainStream serves a scripted reply and then blocks on Read
// until its read deadline passes, like a peer that never finishes its
// direction. It records how it was released.
type blockingDrainStream struct {
	serve *bytes.Reader

	mu          sync.Mutex
	deadline    time.Time
	closed      bool
	cancelRead  bool
	cancelWrite bool
}

var errSimulatedTimeout = errors.New("simulated i/o timeout")

func (s *blockingDrainStream) Read(p []byte) (int, error) {
	if s.serve != nil && s.serve.Len() > 0 {
		return s.serve.Read(p)
	}
	s.mu.Lock()
	dl := s.deadline
	s.mu.Unlock()
	if !dl.IsZero() {
		if d := time.Until(dl); d > 0 {
			time.Sleep(d)
		}
	} else {
		time.Sleep(time.Second) // no deadline set: block long enough to count as a hang
	}
	return 0, errSimulatedTimeout
}

func (s *blockingDrainStream) Write(p []byte) (int, error) { return len(p), nil }
func (s *blockingDrainStream) Close() error                { s.closed = true; return nil }
func (s *blockingDrainStream) CancelRead(uint64)           { s.cancelRead = true }
func (s *blockingDrainStream) CancelWrite(uint64)          { s.cancelWrite = true }
func (s *blockingDrainStream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.deadline = t
	s.mu.Unlock()
	return nil
}

// After its Ack, SendEvent finishes the stream cleanly: FIN, then the
// edge's FIN read to EOF, with no reset. A reset on clean completion could
// discard a frame still buffered for the peer.
func TestSendEventDrainsAfterAck(t *testing.T) {
	s := &recordingStream{serve: bytes.NewReader(edgeReplyFrame(t, ackReply())), err: io.EOF}
	d := &Dock{conn: &rpcConn{s: s}}

	if err := d.SendEvent(context.Background(), []byte("loc"), []byte("payload")); err != nil {
		t.Fatalf("SendEvent = %v", err)
	}
	if !s.closed {
		t.Fatal("SendEvent did not close the write direction")
	}
	if s.cancelRead || s.cancelWrite {
		t.Fatal("a cleanly acknowledged SendEvent reset its stream")
	}
}

// An edge that acknowledges but never finishes its direction cannot hang
// SendEvent: the bounded drain times out and resets the stream, so it
// still retires.
func TestSendEventTeardownTimesOutToReset(t *testing.T) {
	old := drainTimeout
	drainTimeout = 50 * time.Millisecond
	t.Cleanup(func() { drainTimeout = old })
	s := &blockingDrainStream{serve: bytes.NewReader(edgeReplyFrame(t, ackReply()))}
	d := &Dock{conn: &rpcConn{s: s}}

	done := make(chan error, 1)
	go func() { done <- d.SendEvent(context.Background(), []byte("loc"), []byte("payload")) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("SendEvent = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendEvent hung: the bounded drain did not time out")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed || !s.cancelRead || !s.cancelWrite {
		t.Fatalf("closed=%v cancelRead=%v cancelWrite=%v, want FIN then a reset of both directions",
			s.closed, s.cancelRead, s.cancelWrite)
	}
}

// A Nak on SendEvent surfaces as a NakError carrying its code.
func TestSendEventNakTyped(t *testing.T) {
	reply := edgeReplyFrame(t, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Nak{
		Nak: &dpb.Nak{Code: dpb.NakCode_NAK_CODE_TARGET_GONE},
	}})
	d := &Dock{conn: &rpcConn{s: &recordingStream{serve: bytes.NewReader(reply), err: io.EOF}}}
	err := d.SendEvent(context.Background(), []byte("loc"), nil)
	var nak NakError
	if !errors.As(err, &nak) || nak.Code != dpb.NakCode_NAK_CODE_TARGET_GONE {
		t.Fatalf("SendEvent = %v, want NakError NAK_CODE_TARGET_GONE", err)
	}
	if got := nak.Error(); got != "dock: delivery refused: NAK_CODE_TARGET_GONE" {
		t.Fatalf("NakError text = %q", got)
	}
}

// serveOpenLane runs the fake edge's side of one OpenLane verb: it checks
// the request, replies, optionally runs then (an attach), and finishes its
// direction so the dock's drain completes. The served stream comes back
// on the returned channel for release checks.
func (e *laneEdge) serveOpenLane(check func(*dpb.OpenLane), reply *dpb.EdgeToRequester, then func()) <-chan openedStream {
	served := make(chan openedStream, 1)
	go func() {
		os := <-e.conn.opened
		defer func() { served <- os }()
		kind := make([]byte, 1)
		if _, err := io.ReadFull(os.edge, kind); err != nil || kind[0] != wire.StreamKindDelivery {
			e.t.Errorf("verb stream kind byte = %v, %v", kind, err)
			return
		}
		var req dpb.RequesterToEdge
		if err := wire.ReadFrame(os.edge, &req, 0); err != nil {
			e.t.Errorf("verb frame: %v", err)
			return
		}
		ol := req.GetOpenLane()
		if ol == nil {
			e.t.Errorf("verb was not OpenLane: %v", req.GetMsg())
			return
		}
		if check != nil {
			check(ol)
		}
		if err := wire.WriteFrame(os.edge, reply); err != nil {
			e.t.Errorf("verb reply: %v", err)
			return
		}
		if then != nil {
			then()
		}
		_ = os.edge.Close() // the edge's FIN: the dock's drain completes
	}()
	return served
}

// OpenLane sends its targets, classes and metadata; LaneOpened names the
// lane on this dock's connection; this dock's own LaneAttached carries no
// metadata, since this dock supplied it; and the returned lane is the
// live registry lane, with the confirms reporting what was attached.
func TestOpenLaneEstablishes(t *testing.T) {
	d, e := newLaneDock(t)
	gen := generation.DockGen{Edge: generation.EdgeTag{Incarnation: "inc", LeaseID: "lease"}, Slot: 1, Epoch: 2, Nonce: "n"}
	genPB, err := wire.GenToProtoV2(gen)
	if err != nil {
		t.Fatalf("GenToProtoV2: %v", err)
	}

	e.serveOpenLane(func(ol *dpb.OpenLane) {
		if len(ol.GetTargets()) != 1 || !bytes.Equal(ol.GetTargets()[0].GetLocator(), []byte("loc")) {
			e.t.Errorf("targets = %v", ol.GetTargets())
		}
		if ol.GetTargets()[0].GetExpectedPrincipal() != "spiffe://example.com/target" {
			e.t.Errorf("expected_principal = %q", ol.GetTargets()[0].GetExpectedPrincipal())
		}
		if ol.GetLaneClass() != wire.LaneClassStream {
			e.t.Errorf("lane_class = %#x", ol.GetLaneClass())
		}
		if !bytes.Equal(ol.GetMetadata(), []byte("m")) {
			e.t.Errorf("metadata = %q", ol.GetMetadata())
		}
	}, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_LaneOpened{LaneOpened: &dpb.LaneOpened{
		LaneId:         11,
		TargetConfirms: []*dpb.LaneTargetConfirm{{Gen: genPB, Principal: "spiffe://example.com/target"}},
	}}}, func() {
		e.attach(11, wire.LaneClassStream, "spiffe://example.com/target", nil)
	})

	lane, confirms, err := d.OpenLane(laneCtx(t),
		[]LaneTarget{{Locator: []byte("loc"), ExpectedPrincipal: "spiffe://example.com/target"}},
		wire.LaneClassStream, []byte("m"))
	if err != nil {
		t.Fatalf("OpenLane: %v", err)
	}
	if lane == nil || lane.ID() != 11 {
		t.Fatalf("lane = %+v, want ID 11", lane)
	}
	if len(lane.Metadata()) != 0 {
		t.Errorf("requester-side metadata = %q, want empty", lane.Metadata())
	}
	if len(confirms) != 1 || confirms[0].Principal != "spiffe://example.com/target" || confirms[0].Gen != gen {
		t.Fatalf("confirms = %+v", confirms)
	}

	// The returned lane is live: a later LaneClosed reaches it.
	e.closeLane(11, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED)
	select {
	case <-lane.Closed():
	case <-time.After(5 * time.Second):
		t.Fatal("the returned lane did not observe LaneClosed")
	}
}

// A refused OpenLane surfaces the Nak as a NakError, and the delivery
// stream is released.
func TestOpenLaneNakTyped(t *testing.T) {
	d, e := newLaneDock(t)
	served := e.serveOpenLane(nil, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Nak{
		Nak: &dpb.Nak{Code: dpb.NakCode_NAK_CODE_LANE_LIMIT},
	}}, nil)

	_, _, err := d.OpenLane(laneCtx(t), []LaneTarget{{Locator: []byte("loc")}}, wire.LaneClassStream, nil)
	var nak NakError
	if !errors.As(err, &nak) || nak.Code != dpb.NakCode_NAK_CODE_LANE_LIMIT {
		t.Fatalf("OpenLane = %v, want NakError NAK_CODE_LANE_LIMIT", err)
	}
	os := <-served
	os.s.mu.Lock()
	released := os.s.closed || len(os.s.cancelRead) > 0 || len(os.s.cancelWrite) > 0
	os.s.mu.Unlock()
	if !released {
		t.Fatal("the refused delivery stream was not released")
	}
}

// OpenLane takes one or two targets. Any other number is refused locally,
// and no delivery stream is opened.
func TestOpenLaneCardinalityLocal(t *testing.T) {
	d, _ := newLaneDock(t)
	for _, n := range []int{0, 3} {
		targets := make([]LaneTarget, n)
		for i := range targets {
			targets[i] = LaneTarget{Locator: []byte("loc")}
		}
		if _, _, err := d.OpenLane(laneCtx(t), targets, wire.LaneClassStream, nil); err == nil {
			t.Errorf("%d targets accepted", n)
		}
	}
	if got := d.conn.(*laneConn).opens.Load(); got != 0 {
		t.Fatalf("refused shapes opened %d delivery streams, want 0", got)
	}
}

// On the fallback transport, which has no datagrams, a class set that
// includes flow is refused locally with NAK_CODE_ADAPTER_MISMATCH before
// any stream is opened. Positive control: a stream-only lane on the same
// dock reaches the edge.
func TestOpenLaneFlowOnFallbackRefusedLocally(t *testing.T) {
	d, e := newLaneDockOn(t, wire.TransportTCPFallback)

	_, _, err := d.OpenLane(laneCtx(t), []LaneTarget{{Locator: []byte("loc")}},
		wire.LaneClassStream|wire.LaneClassFlow, nil)
	var nak NakError
	if !errors.As(err, &nak) || nak.Code != dpb.NakCode_NAK_CODE_ADAPTER_MISMATCH {
		t.Fatalf("OpenLane = %v, want NakError NAK_CODE_ADAPTER_MISMATCH", err)
	}
	if got := d.conn.(*laneConn).opens.Load(); got != 0 {
		t.Fatalf("the local refusal opened %d delivery streams, want 0", got)
	}

	e.serveOpenLane(nil, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_LaneOpened{
		LaneOpened: &dpb.LaneOpened{LaneId: 2, TargetConfirms: []*dpb.LaneTargetConfirm{{Principal: "spiffe://example.com/target"}}},
	}}, func() { e.attach(2, wire.LaneClassStream, "", nil) })
	lane, _, err := d.OpenLane(laneCtx(t), []LaneTarget{{Locator: []byte("loc")}}, wire.LaneClassStream, nil)
	if err != nil || lane == nil || lane.ID() != 2 {
		t.Fatalf("stream-only OpenLane on the fallback: lane=%v err=%v", lane, err)
	}
}

// With the flow class on QUIC, OpenLane reaches the edge, and the lane
// then carries flows in both directions.
func TestOpenLaneFlowClassOnQUIC(t *testing.T) {
	d, e, fc := newFlowDock(t)
	e.serveOpenLane(func(ol *dpb.OpenLane) {
		if ol.GetLaneClass() != wire.LaneClassStream|wire.LaneClassFlow {
			e.t.Errorf("lane_class = %#x, want stream|flow", ol.GetLaneClass())
		}
	}, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_LaneOpened{LaneOpened: &dpb.LaneOpened{
		LaneId:         6,
		TargetConfirms: []*dpb.LaneTargetConfirm{{Principal: "spiffe://example.com/target"}},
	}}}, func() {
		e.attach(6, wire.LaneClassStream|wire.LaneClassFlow, "spiffe://example.com/target", nil)
	})

	lane, _, err := d.OpenLane(laneCtx(t), []LaneTarget{{Locator: []byte("loc")}},
		wire.LaneClassStream|wire.LaneClassFlow, nil)
	if err != nil {
		t.Fatalf("flow OpenLane on QUIC: %v", err)
	}
	if err := lane.SendFlow(1, []byte("ping")); err != nil {
		t.Fatalf("SendFlow: %v", err)
	}
	if got := <-fc.sent; !bytes.Equal(got, []byte{0x06, 0x01, 'p', 'i', 'n', 'g'}) {
		t.Fatalf("sent %x, want the attribution prefix and ping", got)
	}
	fc.inbound <- dgram(6, 2, "pong")
	flowID, payload, err := lane.ReceiveFlow(laneCtx(t))
	if err != nil || flowID != 2 || !bytes.Equal(payload, []byte("pong")) {
		t.Fatalf("ReceiveFlow = (%d, %q, %v), want (2, \"pong\")", flowID, payload, err)
	}
}

// With two targets this dock is a third party: LaneOpened names no lane
// on its connection, OpenLane returns no Lane, and the confirms report
// both attachments.
func TestOpenLaneTwoDockReturnsConfirmsOnly(t *testing.T) {
	d, e := newLaneDock(t)
	e.serveOpenLane(func(ol *dpb.OpenLane) {
		if len(ol.GetTargets()) != 2 {
			e.t.Errorf("targets = %d, want 2", len(ol.GetTargets()))
		}
	}, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_LaneOpened{LaneOpened: &dpb.LaneOpened{
		TargetConfirms: []*dpb.LaneTargetConfirm{{Principal: "a"}, {Principal: "b"}},
	}}}, nil)

	lane, confirms, err := d.OpenLane(laneCtx(t),
		[]LaneTarget{{Locator: []byte("la")}, {Locator: []byte("lb")}},
		wire.LaneClassStream|wire.LaneClassSpliceLeg, nil)
	if err != nil {
		t.Fatalf("OpenLane: %v", err)
	}
	if lane != nil {
		t.Fatalf("a lane between two other docks returned a Lane: %+v", lane)
	}
	if len(confirms) != 2 || confirms[0].Principal != "a" || confirms[1].Principal != "b" {
		t.Fatalf("confirms = %+v", confirms)
	}
}

// LaneOpened must carry one confirm per target, and a lane id for a lane
// that includes this dock. A reply that breaks either is refused as
// malformed, not reported as a timeout.
func TestOpenLaneRefusesMalformedLaneOpened(t *testing.T) {
	cases := []struct {
		name    string
		targets []LaneTarget
		reply   *dpb.LaneOpened
	}{
		{"one target, zero confirms", []LaneTarget{{Locator: []byte("loc")}}, &dpb.LaneOpened{LaneId: 7}},
		{"two targets, one confirm", []LaneTarget{{Locator: []byte("la")}, {Locator: []byte("lb")}},
			&dpb.LaneOpened{TargetConfirms: []*dpb.LaneTargetConfirm{{Principal: "a"}}}},
		{"one target, no lane id", []LaneTarget{{Locator: []byte("loc")}},
			&dpb.LaneOpened{TargetConfirms: []*dpb.LaneTargetConfirm{{Principal: "a"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, e := newLaneDock(t)
			e.serveOpenLane(nil, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_LaneOpened{LaneOpened: tc.reply}}, nil)
			lane, confirms, err := d.OpenLane(laneCtx(t), tc.targets, wire.LaneClassStream, nil)
			if err == nil {
				t.Fatalf("malformed LaneOpened accepted: lane=%v confirms=%v", lane, confirms)
			}
			if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
				t.Fatalf("malformed LaneOpened surfaced as a context error: %v", err)
			}
		})
	}
}

// A dock without a control stream holds no lanes, so OpenLane refuses
// before opening anything.
func TestOpenLaneRequiresAdmittedDock(t *testing.T) {
	conn := newLaneConn()
	t.Cleanup(conn.cancel)
	d := &Dock{conn: conn, transport: wire.TransportQUIC, drained: make(chan struct{})}
	if _, _, err := d.OpenLane(laneCtx(t), []LaneTarget{{Locator: []byte("loc")}}, wire.LaneClassStream, nil); err == nil {
		t.Fatal("OpenLane succeeded on a dock without a control stream")
	}
	if got := conn.opens.Load(); got != 0 {
		t.Fatalf("opened %d delivery streams, want 0", got)
	}
}
