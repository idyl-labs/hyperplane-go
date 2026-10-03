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
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

// dock_bench_test.go: the per-stream and per-datagram hot paths of a
// dock: dispatching an inbound stream on its first byte, claiming it,
// opening a lane stream, and sending and receiving flow items. The transport is a non-blocking fake, so the numbers measure
// this package's work rather than a network.

// benchLaneDock builds a dock over the lane fake with lane 1 live.
func benchLaneDock(b *testing.B) (*Dock, *laneConn, *Lane) {
	b.Helper()
	conn := newLaneConn()
	b.Cleanup(conn.cancel)
	d := &Dock{conn: conn, transport: wire.TransportQUIC, drained: make(chan struct{})}
	d.laneAttached(&dockpb.LaneAttached{LaneId: 1, LaneClass: wire.LaneClassStream})
	return d, conn, d.laneset().lanes[1]
}

// BenchmarkInboundDispatchLaneStream: first-byte dispatch and attribution
// parse of one inbound lane stream, then its claim by Lane.AcceptStream.
func BenchmarkInboundDispatchLaneStream(b *testing.B) {
	d, _, lane := benchLaneDock(b)
	set := d.laneset()
	raw := mustLaneHeader(b, wire.LaneStreamHeader{LaneID: 1, Class: wire.LaneStreamClassPassthrough, Header: []byte("pod-a")})
	ctx := context.Background()
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		set.sem <- struct{}{}
		d.routeStream(set, newBytesStream(raw))
		if _, err := lane.AcceptStream(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkInboundDispatchRPC: first-byte dispatch of one inbound RPC
// stream, then AcceptRPC's preface decode.
func BenchmarkInboundDispatchRPC(b *testing.B) {
	d, _, _ := benchLaneDock(b)
	set := d.laneset()
	raw := mustFrame(b, &dpb.RpcOpen{Metadata: []byte(ReportRPCMetadata)})
	ctx := context.Background()
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		set.sem <- struct{}{}
		d.routeStream(set, newBytesStream(raw))
		if _, _, err := d.AcceptRPC(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLaneAcceptStreamThroughPump: one inbound lane stream end to
// end through the accept pump: accept, a routing goroutine, delivery to
// the lane, and the claim.
func BenchmarkLaneAcceptStreamThroughPump(b *testing.B) {
	_, conn, lane := benchLaneDock(b)
	raw := mustLaneHeader(b, wire.LaneStreamHeader{LaneID: 1, Class: wire.LaneStreamClassPassthrough})
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		conn.accepts <- newBytesStream(raw)
		if _, err := lane.AcceptStream(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// discardConn opens streams that accept every write and never block.
type discardConn struct{ *laneConn }

func (discardConn) OpenStreamSync(context.Context) (transportStream, error) {
	return newBytesStream(nil), nil
}

// BenchmarkLaneOpenStream: encoding and writing the attribution header
// of one locally opened lane stream.
func BenchmarkLaneOpenStream(b *testing.B) {
	lc := newLaneConn()
	b.Cleanup(lc.cancel)
	d := &Dock{conn: discardConn{lc}, transport: wire.TransportQUIC, drained: make(chan struct{})}
	d.laneAttached(&dockpb.LaneAttached{LaneId: 1, LaneClass: wire.LaneClassStream})
	lane := d.laneset().lanes[1]
	hdr := []byte("pod-a")
	ctx := context.Background()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := lane.OpenStream(ctx, wire.LaneStreamClassE2EMTLS, hdr); err != nil {
			b.Fatal(err)
		}
	}
}

// discardDatagrams accepts every datagram sent and never receives one.
type discardDatagrams struct{ *laneConn }

func (discardDatagrams) SendDatagram([]byte) error { return nil }

func (d discardDatagrams) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-d.ctx.Done()
	return nil, d.ctx.Err()
}

// BenchmarkLaneSendFlow: encoding one flow item's attribution prefix and
// handing the datagram to the transport.
func BenchmarkLaneSendFlow(b *testing.B) {
	lc := newLaneConn()
	b.Cleanup(lc.cancel)
	d := &Dock{conn: discardDatagrams{lc}, transport: wire.TransportQUIC, drained: make(chan struct{})}
	d.laneAttached(&dockpb.LaneAttached{LaneId: 1, LaneClass: wire.LaneClassFlow})
	lane := d.laneset().lanes[1]
	payload := make([]byte, 1024)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		if err := lane.SendFlow(7, payload); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLaneReceiveFlowThroughPump: one inbound flow item end to end
// through the datagram pump: parse, attribution to its lane, queueing,
// and the claim by ReceiveFlow.
func BenchmarkLaneReceiveFlowThroughPump(b *testing.B) {
	fc := newFlowConn()
	b.Cleanup(fc.cancel)
	d := &Dock{conn: fc, transport: wire.TransportQUIC, drained: make(chan struct{})}
	d.laneAttached(&dockpb.LaneAttached{LaneId: 1, LaneClass: wire.LaneClassFlow})
	lane := d.laneset().lanes[1]
	raw, err := wire.AppendLaneDatagram(nil, 1, 7, make([]byte, 1024))
	if err != nil {
		b.Fatal(err)
	}
	ctx := context.Background()
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		fc.inbound <- raw
		if _, _, err := lane.ReceiveFlow(ctx); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkKeepaliveDelay: the per-interval jitter draw of every live
// dock.
func BenchmarkKeepaliveDelay(b *testing.B) {
	b.ReportAllocs()
	var sink time.Duration
	for b.Loop() {
		sink += keepaliveDelay(20 * time.Second)
	}
	_ = sink
}
