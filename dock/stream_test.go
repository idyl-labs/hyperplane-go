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
	"os"
	"strings"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

// stream_test.go: the building blocks for stream protocols built on a
// dock (OpenStream, WaitLane and NewRPC) against the fake edge.

// OpenStream returns a new stream on the dock's connection and writes
// nothing to it: the first bytes the edge reads are the caller's, and the
// stream carries bytes both ways.
func TestOpenStreamIsRawAndCarriesBothWays(t *testing.T) {
	d, e := newLaneDock(t)
	s, err := d.OpenStream(laneCtx(t))
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	opened := <-e.conn.opened

	go func() { _, _ = s.Write([]byte{0x7f, 'h', 'i'}) }()
	got := make([]byte, 3)
	if _, err := io.ReadFull(opened.edge, got); err != nil {
		t.Fatalf("edge read: %v", err)
	}
	if string(got) != "\x7fhi" {
		t.Fatalf("edge read %q, want the caller's bytes and nothing before them", got)
	}

	go func() { _, _ = opened.edge.Write([]byte("ok")) }()
	reply := make([]byte, 2)
	if _, err := io.ReadFull(s, reply); err != nil || string(reply) != "ok" {
		t.Fatalf("stream read = %q, %v", reply, err)
	}
	opened.s.notCanceled(t)
}

// OpenStream fails with the transport's error, and the returned Stream is
// a nil interface rather than an interface holding a nil stream.
func TestOpenStreamErrorReturnsNilStream(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	conn := &fallbackTransportConn{conn: fallback.Client(client, 0)}
	d := &Dock{conn: conn, transport: wire.TransportTCPFallback, drained: make(chan struct{})}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, err := d.OpenStream(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("OpenStream with a canceled context = %v, want context.Canceled", err)
	}
	if s != nil {
		t.Fatalf("OpenStream returned %T alongside its error, want a nil Stream", s)
	}
}

// NewRPC gives a stream the RPC surface: reads and writes pass through,
// Close half-closes the write side without a reset, and Abort resets both
// directions with DockCodeProtocol.
func TestNewRPCWrapsStream(t *testing.T) {
	edge, s := newLanePipe()
	t.Cleanup(func() { _ = edge.Close() })
	rpc := NewRPC(s)

	go func() { _, _ = edge.Write([]byte("req")) }()
	got := make([]byte, 3)
	if _, err := io.ReadFull(rpc, got); err != nil || string(got) != "req" {
		t.Fatalf("RPC read = %q, %v", got, err)
	}
	go func() { _, _ = rpc.Write([]byte("resp")) }()
	reply := make([]byte, 4)
	if _, err := io.ReadFull(edge, reply); err != nil || string(reply) != "resp" {
		t.Fatalf("edge read = %q, %v", reply, err)
	}

	if err := rpc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if !closed {
		t.Fatal("Close did not close the write side")
	}
	s.notCanceled(t)

	rpc.Abort()
	s.waitCanceled(t, wire.DockCodeProtocol)
}

// An RPC from NewRPC satisfies RPCStream, so NewRPCConn adapts it like
// one from AcceptRPC.
func TestNewRPCAdaptsToConn(t *testing.T) {
	edge, s := newLanePipe()
	t.Cleanup(func() { _ = edge.Close() })
	var stream RPCStream = NewRPC(s)
	conn := NewRPCConn(stream, nil)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s.waitCanceled(t, wire.DockCodeProtocol)
}

// WaitLane returns a lane that attaches after the wait began, and claims
// it: AcceptLane does not return it as well.
func TestWaitLaneReturnsLaneAttachedLater(t *testing.T) {
	d, e := newLaneDock(t)
	ctx := laneCtx(t)
	got := make(chan *Lane, 1)
	go func() {
		l, err := d.WaitLane(ctx, 7)
		if err != nil {
			t.Errorf("WaitLane: %v", err)
		}
		got <- l
	}()
	// Give WaitLane time to block, so the lane arrives while it waits.
	// The result is the same if it has not blocked yet.
	time.Sleep(20 * time.Millisecond)
	e.attach(7, wire.LaneClassStream, "spiffe://example.com/peer", []byte("m"))

	var l *Lane
	select {
	case l = <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("WaitLane did not return after LaneAttached")
	}
	if l == nil || l.ID() != 7 || string(l.Metadata()) != "m" {
		t.Fatalf("WaitLane returned %+v, want lane 7 with its metadata", l)
	}
	if _, err := d.AcceptLane(shortCtx(t)); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("AcceptLane after WaitLane = %v, want a deadline (the lane was claimed)", err)
	}
}

// WaitLane finds a lane that attached before the wait and claims only
// that lane: others stay queued for AcceptLane in their order.
func TestWaitLaneClaimsOnlyItsLane(t *testing.T) {
	d, e := newLaneDock(t)
	for _, id := range []uint64{3, 4, 5} {
		e.attach(id, wire.LaneClassStream, "spiffe://example.com/peer", nil)
	}
	l, err := d.WaitLane(laneCtx(t), 4)
	if err != nil || l.ID() != 4 {
		t.Fatalf("WaitLane(4) = %v, %v", l, err)
	}
	for _, want := range []uint64{3, 5} {
		got, err := d.AcceptLane(laneCtx(t))
		if err != nil || got.ID() != want {
			t.Fatalf("AcceptLane = %v, %v; want lane %d", got, err, want)
		}
	}
}

// A lane AcceptLane has already returned is returned again, as the same
// *Lane.
func TestWaitLaneReturnsLaneAlreadyAccepted(t *testing.T) {
	d, e := newLaneDock(t)
	accepted := attachLane(t, d, e, 9, wire.LaneClassStream)
	l, err := d.WaitLane(laneCtx(t), 9)
	if err != nil || l != accepted {
		t.Fatalf("WaitLane(9) = %p, %v; want the accepted lane %p", l, err, accepted)
	}
}

// A lane that ended before WaitLane found it returns ErrLaneClosed with
// its cause.
func TestWaitLaneEndedLaneReturnsCause(t *testing.T) {
	d, e := newLaneDock(t)
	ended := attachLane(t, d, e, 6, wire.LaneClassStream)
	endLane(t, e, ended, dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED)

	_, err := d.WaitLane(laneCtx(t), 6)
	if !errors.Is(err, ErrLaneClosed) {
		t.Fatalf("WaitLane on an ended lane = %v, want ErrLaneClosed", err)
	}
	if !strings.Contains(err.Error(), dockpb.LaneCloseCause_LANE_CLOSE_CAUSE_DRAINED.String()) {
		t.Fatalf("WaitLane error %q does not name the cause", err)
	}
}

// WaitLane returns when its context is canceled and when the dock ends.
func TestWaitLaneReturnsOnCancelAndDockEnd(t *testing.T) {
	d, _ := newLaneDock(t)
	if _, err := d.WaitLane(shortCtx(t), 7); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitLane with an expiring context = %v, want context.DeadlineExceeded", err)
	}

	d2, e2 := newLaneDock(t)
	e2.conn.cancel()
	if _, err := d2.WaitLane(laneCtx(t), 7); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitLane on an ended dock = %v, want the connection's context.Canceled", err)
	}
}

// finishStream serves fixed bytes and then end, the error a read past
// them returns, and records how the stream was finished.
type finishStream struct {
	r        *bytes.Reader
	end      error
	closed   bool
	deadline time.Time
	cancels  []uint64
}

func (s *finishStream) Read(p []byte) (int, error) {
	if s.r.Len() == 0 {
		return 0, s.end
	}
	return s.r.Read(p)
}
func (s *finishStream) Write(p []byte) (int, error)       { return len(p), nil }
func (s *finishStream) Close() error                      { s.closed = true; return nil }
func (s *finishStream) CancelRead(code uint64)            { s.cancels = append(s.cancels, code) }
func (s *finishStream) CancelWrite(code uint64)           { s.cancels = append(s.cancels, code) }
func (s *finishStream) SetReadDeadline(t time.Time) error { s.deadline = t; return nil }

// FinishStream closes the write direction, reads the peer's remaining
// data under a bounded deadline, and resets nothing when the peer
// finishes; when the read ends in an error, such as the deadline, both
// directions are reset with DockCodeProtocol.
func TestFinishStream(t *testing.T) {
	clean := &finishStream{r: bytes.NewReader([]byte("tail")), end: io.EOF}
	before := time.Now()
	FinishStream(clean)
	if !clean.closed || clean.r.Len() != 0 || len(clean.cancels) != 0 {
		t.Fatalf("clean finish: closed=%v unread=%d cancels=%v", clean.closed, clean.r.Len(), clean.cancels)
	}
	if clean.deadline.Before(before) || clean.deadline.After(time.Now().Add(drainTimeout)) {
		t.Fatalf("read deadline %v is not bounded by drainTimeout", clean.deadline)
	}

	stalled := &finishStream{r: bytes.NewReader(nil), end: os.ErrDeadlineExceeded}
	FinishStream(stalled)
	if !stalled.closed {
		t.Fatal("stalled finish did not close the write direction")
	}
	if len(stalled.cancels) != 2 || stalled.cancels[0] != wire.DockCodeProtocol || stalled.cancels[1] != wire.DockCodeProtocol {
		t.Fatalf("stalled finish cancels = %v, want both directions with DockCodeProtocol", stalled.cancels)
	}
}
