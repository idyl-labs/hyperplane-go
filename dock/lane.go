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
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

// The client side of lanes. A lane is an association between two docks,
// held by the edge, authorized when it is established and bound to the
// generations of both docks. Bidirectional streams attach to a lane with
// a raw attribution header (wire.LaneStreamHeader); there is no protobuf
// framing on a lane stream's byte path.
//
// Lane lifecycle (LaneAttached and LaneClosed) arrives on the dock's
// control stream. Lane streams opened by the peer arrive as edge-opened
// bidirectional streams whose first byte is wire.StreamKindLane; inbound
// RPC streams always begin with 0x00, so the first byte separates the two.
//
// The control stream is the only source of lane state. Stream-level reset
// codes inform per-stream retry only, and this package never derives lane
// state from them.

// laneAttachWait bounds two waits on an inbound stream: reading its
// first byte and attribution header, and holding an attributed stream
// that names a lane the dock has not yet seen. The edge sends
// LaneAttached before it opens a lane's streams, but QUIC does not order
// delivery across streams, so such a stream is held while pending control
// frames are processed. After the bound the stream is a protocol violation
// and is reset with wire.DockCodeProtocol. The default matches the edge's
// own bound on reading an attribution header. It is a variable so tests
// can shorten it.
var laneAttachWait = 10 * time.Second

// ErrLaneClosed is returned for operations on a lane that has ended. An
// ended lane never comes back; a new association needs a new lane.
var ErrLaneClosed = errors.New("dock: lane closed")

// Lane is one lane attached to this dock, live or ended, as announced by
// a LaneAttached frame on the dock's control stream.
type Lane struct {
	dock *Dock

	id       uint64
	classes  uint64
	peer     string
	metadata []byte

	closed chan struct{}
	cause  dockpb.LaneCloseCause

	streams []*LaneStream // accepted and attributed, not yet claimed by AcceptStream
}

// ID is the lane's identifier. It is scoped to this dock's connection:
// the same value names nothing on any other connection.
func (l *Lane) ID() uint64 { return l.id }

// Classes is the granted lane class bitset (the wire.LaneClass*
// constants). The edge grants exactly the requested set of classes or
// refuses the lane; it never grants a narrower set.
func (l *Lane) Classes() uint64 { return l.classes }

// Metadata is the application metadata supplied when the lane was
// requested. The fabric carries it without interpreting it. It is
// delivered to the target dock; on the dock that requested the lane it is
// empty, because that side supplied it.
func (l *Lane) Metadata() []byte { return l.metadata }

// PeerPrincipal is the identity the fabric reports for the lane's other
// end. It is advisory, suitable for display and logging, and must not be
// used to authorize the peer: an application that needs to authenticate
// its peer does so through its own end-to-end secured channel over the
// lane.
func (l *Lane) PeerPrincipal() string { return l.peer }

// Closed is closed when the lane ends. After it fires, CloseCause
// reports why.
func (l *Lane) Closed() <-chan struct{} { return l.closed }

// CloseCause reports why the lane ended. It is valid only after Closed
// has fired. Causes 1 through 6 mean the lane was torn down and its
// streams were reset; LANE_CLOSE_CAUSE_DRAINED means the lane ended after
// its existing streams ran to completion.
func (l *Lane) CloseCause() dockpb.LaneCloseCause { return l.cause }

// OpenStream opens one bidirectional stream attributed to this lane. The
// attribution header (the lane stream kind byte, this lane's id, the
// declared stream class and the opaque hdr) is written before any payload
// byte. It fails locally with ErrLaneClosed if the lane has already ended,
// or with an encoding error if the header cannot be encoded. The edge
// refuses a stream with a stream-level application error code
// (wire.LaneCodeDraining, wire.DockCodeOverloaded or wire.DockCodeProtocol)
// that surfaces on the returned stream's reads and writes; such a code
// informs per-stream retry only and says nothing about the lane.
func (l *Lane) OpenStream(ctx context.Context, class byte, hdr []byte) (*LaneStream, error) {
	// Encode before opening so a value with no legal wire form costs no
	// stream, and fail locally on an ended lane, which the edge would
	// refuse with DockCodeProtocol.
	attr, err := wire.AppendLaneHeader(nil, wire.LaneStreamHeader{LaneID: l.id, Class: class, Header: hdr})
	if err != nil {
		return nil, err
	}
	select {
	case <-l.closed:
		return nil, fmt.Errorf("%w (%s)", ErrLaneClosed, l.cause)
	default:
	}
	s, err := l.dock.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.Write(attr); err != nil {
		s.CancelRead(wire.DockCodeProtocol)
		s.CancelWrite(wire.DockCodeProtocol)
		return nil, err
	}
	return &LaneStream{lane: l, class: class, header: hdr, stream: s}, nil
}

// AcceptStream blocks for the next inbound stream attributed to this
// lane. When the lane ends, streams not yet accepted are reset with it,
// and AcceptStream returns ErrLaneClosed. It also returns when ctx is
// canceled or the dock ends.
func (l *Lane) AcceptStream(ctx context.Context) (*LaneStream, error) {
	l.dock.ensurePump()
	set := l.dock.laneset()
	for {
		set.mu.Lock()
		if len(l.streams) > 0 {
			s := l.streams[0]
			l.streams = l.streams[1:]
			rel := s.release
			s.release = nil
			set.mu.Unlock()
			if rel != nil {
				rel()
			}
			return s, nil
		}
		var ended bool
		select {
		case <-l.closed:
			ended = true
		default:
		}
		ch := set.changed
		set.mu.Unlock()
		if ended {
			return nil, fmt.Errorf("%w (%s)", ErrLaneClosed, l.cause)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-l.dock.conn.Context().Done():
			return nil, l.dock.conn.Context().Err()
		case <-ch:
		}
	}
}

// LaneStream is one bidirectional stream attributed to a lane: a
// transparent byte pipe after its attribution header. On QUIC a lane
// stream shares no head-of-line blocking, flow-control window or teardown
// with any other stream on the lane.
type LaneStream struct {
	lane   *Lane
	class  byte
	header []byte
	stream transportStream

	// release returns the accept-backlog slot an inbound stream holds
	// while it waits to be claimed. It is nil once the slot is returned
	// and for locally opened streams. Guarded by the lane registry lock.
	release func()
}

// Lane is the lane this stream is attributed to.
func (s *LaneStream) Lane() *Lane { return s.lane }

// Class is the stream class declared in the attribution header (the
// wire.LaneStreamClass* constants). It is a declaration by the opener,
// not a security property the fabric verifies or enforces.
func (s *LaneStream) Class() byte { return s.class }

// Header is the opaque per-stream application metadata from the
// attribution header, relayed verbatim by the fabric.
func (s *LaneStream) Header() []byte { return s.header }

func (s *LaneStream) Read(p []byte) (int, error)  { return s.stream.Read(p) }
func (s *LaneStream) Write(p []byte) (int, error) { return s.stream.Write(p) }

// Close half-closes the write side (FIN). The fabric relays FIN and reset
// end to end. To finish a stream cleanly, close the write side and read
// the peer's data to EOF; the stream then retires and returns its credit
// without a reset.
func (s *LaneStream) Close() error { return s.stream.Close() }

// Abort resets both directions of the stream (RESET_STREAM and
// STOP_SENDING). It affects this stream only; the lane is unaffected.
func (s *LaneStream) Abort() {
	s.stream.CancelRead(wire.DockCodeProtocol)
	s.stream.CancelWrite(wire.DockCodeProtocol)
}

// AcceptLane blocks for the next lane the edge attached to this dock, as
// announced by LaneAttached on the control stream. Both docks of a lane
// observe its attachment and its end in the same way; a target dock
// learns of new lanes only here. AcceptLane returns when ctx is canceled
// or the dock ends.
func (d *Dock) AcceptLane(ctx context.Context) (*Lane, error) {
	d.ensurePump()
	set := d.laneset()
	for {
		set.mu.Lock()
		if len(set.pending) > 0 {
			l := set.pending[0]
			set.pending = set.pending[1:]
			set.mu.Unlock()
			return l, nil
		}
		ch := set.changed
		set.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-d.conn.Context().Done():
			return nil, d.conn.Context().Err()
		case <-ch:
		}
	}
}

// laneSet is the dock's lane registry plus the inbound bidi-stream
// dispatch state. One mutex guards it all; changed is closed and replaced
// on every mutation (broadcast), so waiters re-check under the lock.
type laneSet struct {
	mu      sync.Mutex
	changed chan struct{}

	lanes   map[uint64]*Lane
	dead    map[uint64]dockpb.LaneCloseCause
	pending []*Lane

	// parked counts attributed streams naming a lane not yet seen, held
	// while pending control frames are processed.
	parked map[uint64]int

	rpc     chan *prefacedStream
	pumpErr error
	pump    sync.Once

	// sem is the accept backlog: one slot per stream accepted ahead of its
	// consumer. An RPC stream holds its slot until it is queued for
	// AcceptRPC; a lane stream holds it until Lane.AcceptStream claims it
	// or the lane's end resets it.
	sem chan struct{}
}

// prefacedStream replays the dispatch-consumed first byte ahead of the
// stream's remaining bytes.
type prefacedStream struct {
	first *byte
	transportStream
}

func (p *prefacedStream) Read(b []byte) (int, error) {
	if p.first != nil && len(b) > 0 {
		b[0] = *p.first
		p.first = nil
		return 1, nil
	}
	return p.transportStream.Read(b)
}

// laneset returns the dock's lane state, initialized on first use so
// docks built as struct literals (tests) and by Open share one path.
func (d *Dock) laneset() *laneSet {
	d.laneOnce.Do(func() {
		d.lane = &laneSet{
			changed: make(chan struct{}),
			lanes:   make(map[uint64]*Lane),
			dead:    make(map[uint64]dockpb.LaneCloseCause),
			parked:  make(map[uint64]int),
			rpc:     make(chan *prefacedStream, acceptBacklog),
			sem:     make(chan struct{}, acceptBacklog),
		}
	})
	return d.lane
}

// acceptBacklog bounds inbound bidirectional streams accepted ahead of
// their consumer. It is the same fixed backlog the fallback transport
// uses, applied here to both transports.
const acceptBacklog = 64

// broadcast wakes every waiter; callers hold mu and waiters re-check
// under it.
func (s *laneSet) broadcast() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// laneAttached applies a control-stream LaneAttached: it installs the
// lane in the registry and queues it for AcceptLane. An id already live
// or ended is a duplicate, because an edge never reuses a lane id on a
// connection, and is dropped, as duplicate LaneClosed frames are.
func (d *Dock) laneAttached(la *dockpb.LaneAttached) {
	id := la.GetLaneId()
	if id == 0 {
		return // lane id 0 is never valid
	}
	set := d.laneset()
	set.mu.Lock()
	defer set.mu.Unlock()
	if _, live := set.lanes[id]; live {
		return
	}
	if _, gone := set.dead[id]; gone {
		return
	}
	l := &Lane{
		dock:     d,
		id:       id,
		classes:  la.GetLaneClass(),
		peer:     la.GetPeerPrincipal(),
		metadata: la.GetMetadata(),
		closed:   make(chan struct{}),
	}
	set.lanes[id] = l
	set.pending = append(set.pending, l)
	set.broadcast()
}

// laneClosed applies a control-stream LaneClosed. It is idempotent:
// duplicates for one lane id are no-ops. The id is recorded as ended
// for the life of the connection, so it is never accepted again.
func (d *Dock) laneClosed(lc *dockpb.LaneClosed) {
	id := lc.GetLaneId()
	set := d.laneset()
	set.mu.Lock()
	defer set.mu.Unlock()
	if _, gone := set.dead[id]; gone {
		return
	}
	set.dead[id] = lc.GetCause()
	l, live := set.lanes[id]
	if !live {
		return // never attached here; recorded so the id stays ended
	}
	delete(set.lanes, id)
	// Streams not yet claimed end with the lane. The local reset carries
	// code 0, the code used for teardown (receivers do not interpret
	// teardown codes), and each stream's backlog slot is returned.
	for _, s := range l.streams {
		s.stream.CancelRead(0)
		s.stream.CancelWrite(0)
		if s.release != nil {
			s.release() // guaranteed non-blocking: the slot is held
			s.release = nil
		}
	}
	l.streams = nil
	l.cause = lc.GetCause() // happens-before any post-Closed read
	close(l.closed)
	set.broadcast()
}

// ensurePump starts the inbound bidirectional stream dispatch exactly
// once. Every consumer of inbound streams (AcceptRPC, AcceptLane and
// Lane.AcceptStream) goes through it; two callers accepting streams
// directly would each take streams meant for the other.
func (d *Dock) ensurePump() {
	set := d.laneset()
	set.pump.Do(func() {
		go d.acceptPump(set)
	})
}

func (d *Dock) acceptPump(set *laneSet) {
	// set.sem bounds streams accepted but not yet claimed by a consumer:
	// streams being routed, streams held for a lane not yet seen, RPC
	// streams waiting to be queued and lane streams waiting to be claimed
	// all hold a slot.
	for {
		set.sem <- struct{}{}
		s, err := d.conn.AcceptStream(context.Background())
		if err != nil {
			<-set.sem
			set.mu.Lock()
			set.pumpErr = err
			set.broadcast()
			set.mu.Unlock()
			return
		}
		go d.routeStream(set, s)
	}
}

// routeStream reads one stream's first byte and dispatches it:
// StreamKindLane goes to the named lane; 0x00, the first byte of every
// RPC frame, goes to AcceptRPC with the byte replayed; any other value
// has no assigned protocol and the stream is reset in both directions
// with DockCodeProtocol. Reading the first byte and the lane header is
// bounded by laneAttachWait.
func (d *Dock) routeStream(set *laneSet, s transportStream) {
	refuse := func() {
		s.CancelRead(wire.DockCodeProtocol)
		s.CancelWrite(wire.DockCodeProtocol)
		<-set.sem
	}
	_ = s.SetReadDeadline(time.Now().Add(laneAttachWait))
	var kind [1]byte
	if _, err := io.ReadFull(s, kind[:]); err != nil {
		refuse()
		return
	}
	switch kind[0] {
	case wire.StreamKindLane:
		h, err := wire.ReadLaneHeader(s)
		if err != nil {
			refuse()
			return
		}
		_ = s.SetReadDeadline(time.Time{})
		d.deliverLaneStream(set, h, s)
	case 0x00:
		_ = s.SetReadDeadline(time.Time{})
		first := byte(0x00)
		select {
		case set.rpc <- &prefacedStream{first: &first, transportStream: s}:
			// Queued for AcceptRPC: from here the RPC channel's own
			// capacity is the bound.
			<-set.sem
		case <-d.conn.Context().Done():
			refuse()
		}
	default:
		refuse()
	}
}

// deliverLaneStream queues an attributed stream on its lane. A stream
// naming a lane not yet seen is held while pending control frames are
// processed, because the edge sent LaneAttached before opening the stream
// but QUIC does not order delivery across streams. A stream still unknown
// after laneAttachWait, or naming an ended lane, is a protocol violation
// and is reset with DockCodeProtocol.
func (d *Dock) deliverLaneStream(set *laneSet, h wire.LaneStreamHeader, s transportStream) {
	deadline := time.Now().Add(laneAttachWait)
	set.mu.Lock()
	for {
		if l, ok := set.lanes[h.LaneID]; ok {
			// The backlog slot travels with the queued stream: it is
			// released when a consumer claims the stream or the lane ends.
			l.streams = append(l.streams, &LaneStream{
				lane: l, class: h.Class, header: h.Header, stream: s,
				release: func() { <-set.sem },
			})
			set.broadcast()
			set.mu.Unlock()
			return
		}
		if _, gone := set.dead[h.LaneID]; gone {
			break
		}
		wait := time.Until(deadline)
		if wait <= 0 || d.conn.Context().Err() != nil {
			break
		}
		set.parked[h.LaneID]++
		ch := set.changed
		set.mu.Unlock()

		timer := time.NewTimer(wait)
		select {
		case <-ch:
		case <-timer.C:
		case <-d.conn.Context().Done():
		}
		timer.Stop()

		set.mu.Lock()
		if set.parked[h.LaneID]--; set.parked[h.LaneID] == 0 {
			delete(set.parked, h.LaneID)
		}
	}
	set.mu.Unlock()
	s.CancelRead(wire.DockCodeProtocol)
	s.CancelWrite(wire.DockCodeProtocol)
	<-set.sem
}
