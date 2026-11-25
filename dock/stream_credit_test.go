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
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/idyl-labs/hyperplane-go/wire"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

// creditLane opens a data dock lane to a scripted edge on transport that
// grants streams bidirectional streams. The edge accepts every stream the
// dock opens, so a stream the dock resets retires and returns its credit.
func creditLane(t *testing.T, transport string, streams int64) *Lane {
	t.Helper()
	edge := newScriptedEdgeGranting(t, newTestPKI(t), transport, streams, serviceWelcome(""))
	d, s := edge.open(nodeConfig(t, edge))
	result := startDataDockOpen(d, laneCtx(t), nil)
	st, _ := edgeServeVerb(laneCtx(t), t, s, serviceReply(9, &dpb.LaneTargetConfirm{Principal: dataDockPrincipal}))
	if err := wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{
		LaneAttached: &dockpb.LaneAttached{LaneId: 9, PeerPrincipal: dataDockPrincipal, LaneClass: wire.LaneClassStream},
	}}); err != nil {
		t.Fatal(err)
	}
	_ = st.Close()
	got := <-result
	if got.err != nil {
		t.Fatalf("data dock lane: %v", got.err)
	}
	requireServiceFIN(t, st)
	go func() {
		for {
			peer, reset, err := acceptResettable(edge.ctx, s)
			if err != nil {
				return
			}
			go func() {
				// Read the stream to its end and, as the fabric relays a
				// reset end to end, reset the edge's half once the dock
				// resets its own, so the stream retires at the edge.
				if _, err := io.Copy(io.Discard, peer); err != nil {
					reset()
				}
			}()
		}
	}()
	return got.lane
}

// acceptResettable accepts a dock-opened stream on s, with a function that
// resets both of the edge's directions of it.
func acceptResettable(ctx context.Context, s *edgeSession) (edgeBidi, func(), error) {
	if s.quic != nil {
		q, err := s.quic.AcceptStream(ctx)
		if err != nil {
			return nil, nil, err
		}
		return q, func() {
			q.CancelRead(quic.StreamErrorCode(wire.DockCodeProtocol))
			q.CancelWrite(quic.StreamErrorCode(wire.DockCodeProtocol))
		}, nil
	}
	f, err := s.mux.AcceptStream(ctx)
	if err != nil {
		return nil, nil, err
	}
	return f, func() {
		f.CancelRead(wire.DockCodeProtocol)
		f.CancelWrite(wire.DockCodeProtocol)
	}, nil
}

// On QUIC, TryOpenStream opens streams while the edge's stream limit
// allows and then returns ErrStreamCredit at once, without waiting and
// without opening anything; OpenStream still waits for credit under its
// context, as it always has; and once one of the dock's streams is reset,
// its credit returns and the next open succeeds.
func TestTryOpenStreamReportsNoStreamCreditAndOpensOnceCreditReturns(t *testing.T) {
	const granted = 8
	lane := creditLane(t, wire.TransportQUIC, granted)

	// The control stream holds one of the granted streams for the dock's
	// life. Open the rest with OpenStream, which also waits out the credit
	// of the lane's one-shot open while the edge retires it.
	open := make([]*LaneStream, 0, granted-1)
	for range granted - 1 {
		ctx, cancel := context.WithTimeout(laneCtx(t), 5*time.Second)
		s, err := lane.OpenStream(ctx, wire.LaneStreamClassE2EMTLS, nil)
		cancel()
		if err != nil {
			t.Fatalf("open %d of %d granted streams: %v", len(open)+1, granted-1, err)
		}
		open = append(open, s)
	}

	started := time.Now()
	s, err := lane.TryOpenStream(wire.LaneStreamClassE2EMTLS, nil)
	if !errors.Is(err, ErrStreamCredit) || s != nil {
		t.Fatalf("TryOpenStream past the edge's limit = %v, %v; want ErrStreamCredit", s, err)
	}
	if waited := time.Since(started); waited > time.Second {
		t.Fatalf("TryOpenStream past the edge's limit took %s; it must not wait", waited)
	}

	ctx, cancel := context.WithTimeout(laneCtx(t), 200*time.Millisecond)
	s, err = lane.OpenStream(ctx, wire.LaneStreamClassE2EMTLS, nil)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) || s != nil {
		t.Fatalf("OpenStream past the edge's limit = %v, %v; want it to wait until its context ends", s, err)
	}

	open[0].Abort()
	ctx, cancel = context.WithTimeout(laneCtx(t), 5*time.Second)
	s, err = lane.OpenStream(ctx, wire.LaneStreamClassE2EMTLS, nil)
	cancel()
	if err != nil {
		t.Fatalf("OpenStream after a stream was reset: %v", err)
	}
	open[0] = s
	if _, err := lane.TryOpenStream(wire.LaneStreamClassE2EMTLS, nil); !errors.Is(err, ErrStreamCredit) {
		t.Fatalf("TryOpenStream with the returned credit taken again = %v, want ErrStreamCredit", err)
	}

	open[1].Abort()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := lane.TryOpenStream(wire.LaneStreamClassE2EMTLS, nil)
		if err == nil {
			s.Abort()
			break
		}
		if !errors.Is(err, ErrStreamCredit) || time.Now().After(deadline) {
			t.Fatalf("TryOpenStream after a stream was reset = %v; want a stream once its credit returns", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	for _, s := range open[2:] {
		s.Abort()
	}
}

// A stream TryOpenStream opens is a lane stream like any other: it leads
// with the exact attribution bytes, then carries the payload.
func TestTryOpenStreamWritesAttributionThenPipes(t *testing.T) {
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
		ls, err := lane.TryOpenStream(wire.LaneStreamClassE2EMTLS, []byte("h"))
		done <- opened{ls, err}
	}()
	os := <-e.conn.opened
	want := laneAttr(8, wire.LaneStreamClassE2EMTLS, "h")
	got := make([]byte, len(want))
	if _, err := io.ReadFull(os.edge, got); err != nil {
		t.Fatalf("attribution read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("attribution = % x, want % x", got, want)
	}
	op := <-done
	if op.err != nil {
		t.Fatalf("TryOpenStream: %v", op.err)
	}
	go func() { _, _ = op.ls.Write([]byte("data")) }()
	buf := make([]byte, 4)
	if _, err := io.ReadFull(os.edge, buf); err != nil || string(buf) != "data" {
		t.Fatalf("payload: %q, %v", buf, err)
	}
	_ = op.ls.Close()
}

// The fallback grants no stream credit ahead of an open: TryOpenStream
// never reports ErrStreamCredit there.
func TestTryOpenStreamOnTheFallbackNeverMeetsALimit(t *testing.T) {
	lane := creditLane(t, wire.TransportTCPFallback, 0)
	for i := range 128 {
		s, err := lane.TryOpenStream(wire.LaneStreamClassE2EMTLS, nil)
		if err != nil {
			t.Fatalf("TryOpenStream %d on the fallback: %v", i, err)
		}
		defer s.Abort()
	}
}

// TryOpenStream on an ended lane fails locally with ErrLaneClosed, as
// OpenStream does, and opens no stream.
func TestTryOpenStreamAfterCloseRefusedLocally(t *testing.T) {
	d, e := newLaneDock(t)
	e.attach(4, wire.LaneClassStream, "peer", nil)
	l, err := d.AcceptLane(laneCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	e.closeLane(4, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_POLICY_REVOKED)
	<-l.Closed()
	if _, err := l.TryOpenStream(wire.LaneStreamClassE2EMTLS, nil); !errors.Is(err, ErrLaneClosed) {
		t.Fatalf("TryOpenStream on an ended lane = %v, want ErrLaneClosed", err)
	}
	if n := e.conn.opens.Load(); n != 0 {
		t.Fatalf("TryOpenStream on an ended lane opened %d streams", n)
	}
}
