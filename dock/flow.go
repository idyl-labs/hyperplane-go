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

	"github.com/idyl-labs/hyperplane-go/wire"
)

// Datagram flows on a lane. A flow item is one QUIC datagram attributed
// to a lane by a prefix of two minimal varints, the lane id and a flow
// id, followed by the payload (wire.AppendLaneDatagram); there is no
// protobuf framing. The lane id is scoped to each dock's own connection,
// and the edge rewrites it hop by hop. The flow id is chosen by the
// sender and is opaque: the fabric passes it through unchanged, and this
// package demultiplexes by lane only.
//
// Flows are best-effort. Nothing on the path refuses an individual
// datagram: queues are bounded and drop their oldest items, a datagram
// naming an unknown or ended lane, or a lane not granted the flow class,
// is dropped without notice, and a send that returns nil is never a
// delivery claim. An application that needs delivery uses lane streams.
//
// A datagram whose leading varint is 0 is transport activity, not a flow
// item: lane id 0 is never valid. The keepalive is the single byte 0x00
// (wire.LaneKeepalive); the receive path discards it.

// ErrFlowClassNotGranted is returned for a flow operation on a lane whose
// granted class set excludes wire.LaneClassFlow. The edge grants exactly
// the requested classes or refuses the lane, so the check is local and
// costs no datagram.
var ErrFlowClassNotGranted = errors.New("dock: flow class not granted on this lane")

// flowBacklog bounds each lane's received flow items not yet claimed by
// ReceiveFlow. A full queue drops its oldest item, so a slow consumer
// sheds old datagrams instead of growing memory.
const flowBacklog = 64

// laneFlow is one received flow item: the sender's flow id and the
// payload.
type laneFlow struct {
	flowID  uint64
	payload []byte
}

// SendFlow sends one flow item on this lane. flowID is chosen by the
// sender and opaque to the fabric; any value is valid, zero included,
// and the receiver reads it unchanged. SendFlow is best-effort: a nil
// error means the transport accepted the datagram, not that it was
// delivered, and an oversized payload returns the transport's error. A
// lane not granted the flow class refuses with ErrFlowClassNotGranted,
// and an ended lane with ErrLaneClosed.
func (l *Lane) SendFlow(flowID uint64, payload []byte) error {
	if l.classes&wire.LaneClassFlow == 0 {
		return ErrFlowClassNotGranted
	}
	select {
	case <-l.closed:
		return fmt.Errorf("%w (%s)", ErrLaneClosed, l.cause)
	default:
	}
	dg, ok := l.dock.conn.(transportDatagramConn)
	if !ok {
		// The edge grants the flow class only on a transport with a
		// datagram plane, so this is reached only against an edge that
		// breaks that rule; it is refused the same way.
		return ErrFlowClassNotGranted
	}
	b, err := wire.AppendLaneDatagram(nil, l.id, flowID, payload)
	if err != nil {
		return err
	}
	return dg.SendDatagram(b)
}

// ReceiveFlow blocks for the next flow item attributed to this lane and
// returns the sender's flow id and the payload unchanged. Datagrams
// naming an unknown or ended lane, or a lane not granted the flow class,
// and datagrams with malformed attribution, are dropped before they
// reach any lane, and keepalives are discarded. At most 64 items are
// held per lane; when more arrive, the oldest are dropped first. When
// the lane ends, its queued items are dropped with it and ReceiveFlow
// returns ErrLaneClosed. It also returns when ctx is canceled or the
// dock ends. A lane not granted the flow class refuses with
// ErrFlowClassNotGranted.
func (l *Lane) ReceiveFlow(ctx context.Context) (flowID uint64, payload []byte, err error) {
	if l.classes&wire.LaneClassFlow == 0 {
		return 0, nil, ErrFlowClassNotGranted
	}
	l.dock.ensurePump()
	set := l.dock.laneset()
	for {
		set.mu.Lock()
		if len(l.flows) > 0 {
			f := l.flows[0]
			l.flows = l.flows[1:]
			set.mu.Unlock()
			return f.flowID, f.payload, nil
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
			return 0, nil, fmt.Errorf("%w (%s)", ErrLaneClosed, l.cause)
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-l.dock.conn.Context().Done():
			return 0, nil, l.dock.conn.Context().Err()
		case <-ch:
		}
	}
}

// datagramPump drains the connection's inbound datagrams for the life of
// the dock. Flow items for a lane granted the flow class are queued on
// that lane, bounded, dropping the oldest. The keepalive form and every
// malformed or unattributable datagram (bad attribution, an unknown or
// ended lane, a lane without the flow class) are dropped without notice,
// because datagrams have no refusal channel. A datagram that arrives
// before its lane's LaneAttached is dropped like any other unattributed
// datagram: only streams are held for a lane not yet seen. The pump ends
// when the connection ends.
func (d *Dock) datagramPump(set *laneSet, dg transportDatagramConn) {
	for {
		b, err := dg.ReceiveDatagram(context.Background())
		if err != nil {
			return // the connection ended, and its datagram plane with it
		}
		f, keepalive, err := wire.ParseLaneDatagram(b)
		if keepalive || err != nil {
			continue // transport activity, or a malformed datagram
		}
		set.mu.Lock()
		l, live := set.lanes[f.LaneID]
		if !live || l.classes&wire.LaneClassFlow == 0 {
			set.mu.Unlock()
			continue // an unknown or ended lane, or no flow class
		}
		if len(l.flows) >= flowBacklog {
			l.flows = l.flows[1:] // the queue is full: drop the oldest
		}
		l.flows = append(l.flows, laneFlow{flowID: f.FlowID, payload: f.Payload})
		set.broadcast()
		set.mu.Unlock()
	}
}
