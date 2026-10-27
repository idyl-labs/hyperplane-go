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
	"io"
	"testing"

	"github.com/idyl-labs/hyperplane-go/wire"
	commonpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/datadock"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

const dataDockPrincipal = "spiffe://zone-a.zone.example.org/node/n1/data-dock"

func startDataDockOpen(d *Dock, ctx context.Context, metadata []byte) <-chan serviceOpenResult {
	result := make(chan serviceOpenResult, 1)
	go func() {
		lane, err := d.OpenDataDockLane(ctx, dataDockPrincipal, metadata)
		result <- serviceOpenResult{lane, err}
	}()
	return result
}

// Only an admitted dock/3 dock asks for a data dock lane, and only for an
// exact canonical principal; anything else is refused before any transport
// is used.
func TestDataDockLaneRefusesLocallyWithoutADock3Dock(t *testing.T) {
	if lane, err := (&Dock{}).OpenDataDockLane(laneCtx(t), dataDockPrincipal, nil); err == nil || lane != nil {
		t.Fatal("unadmitted dock opened a data dock lane")
	}
	d, edge := newLaneDock(t)
	if lane, err := d.OpenDataDockLane(laneCtx(t), dataDockPrincipal, nil); err == nil || lane != nil {
		t.Fatal("dock/2 connection opened a data dock lane")
	}
	d.node = true
	for _, principal := range []string{"", "https://zone-a.zone.example.org/node/n1/data-dock", dataDockPrincipal + "?x=1", dataDockPrincipal + "/"} {
		if lane, err := d.OpenDataDockLane(laneCtx(t), principal, nil); err == nil || lane != nil {
			t.Fatalf("noncanonical target %q opened: %v, %v", principal, lane, err)
		}
	}
	if edge.conn.opens.Load() != 0 {
		t.Fatal("a refused data dock lane used the transport")
	}
}

// A data dock lane opens on one verb, attaches as one STREAM lane to the
// named principal, and carries e2e-mtls streams whose header is the data dock
// header, on both transports.
func TestOpenDataDockLaneOverBothTransports(t *testing.T) {
	header, err := datadock.Header{Host: [16]byte{1}, Sequence: 12, Epoch: 3}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(""))
			d, s := edge.open(nodeConfig(t, edge))
			ctx, cancel := context.WithCancel(laneCtx(t))
			defer cancel()
			result := startDataDockOpen(d, ctx, []byte("opaque"))
			st, verb := edgeServeVerb(laneCtx(t), t, s, serviceReply(9, &dpb.LaneTargetConfirm{Principal: dataDockPrincipal}))
			request := verb.GetOpenDataDockLane()
			if request == nil || request.GetTargetPrincipal() != dataDockPrincipal || string(request.GetMetadata()) != "opaque" {
				t.Fatalf("data dock verb = %v", verb)
			}
			if err := wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{
				LaneAttached: &dockpb.LaneAttached{LaneId: 9, PeerPrincipal: dataDockPrincipal, LaneClass: wire.LaneClassStream},
			}}); err != nil {
				t.Fatal(err)
			}
			_ = st.Close()
			got := <-result
			if got.err != nil || got.lane.ID() != 9 || got.lane.Classes() != wire.LaneClassStream {
				t.Fatalf("data dock lane = %v, %v", got.lane, got.err)
			}
			requireServiceFIN(t, st)
			cancel()
			stream, err := got.lane.OpenStream(laneCtx(t), wire.LaneStreamClassE2EMTLS, header)
			if err != nil {
				t.Fatal(err)
			}
			peer, err := s.acceptStream(laneCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			var kind [1]byte
			if _, err := io.ReadFull(peer, kind[:]); err != nil || kind[0] != wire.StreamKindLane {
				t.Fatalf("lane stream kind = %x, %v", kind, err)
			}
			h, err := wire.ReadLaneHeader(peer)
			if err != nil || h.LaneID != 9 || h.Class != wire.LaneStreamClassE2EMTLS {
				t.Fatalf("stream header = %+v, %v", h, err)
			}
			if decoded, err := datadock.DecodeHeader(h.Header); err != nil || decoded.Sequence != 12 || decoded.Epoch != 3 {
				t.Fatalf("data dock header = %+v, %v", decoded, err)
			}
			_ = stream.Close()
			_ = peer.Close()
		})
	}
}

// Every malformed or mismatched answer is refused, and a typed edge refusal
// keeps its code.
func TestDataDockLaneRefusalsOverBothTransports(t *testing.T) {
	confirm := &dpb.LaneTargetConfirm{Principal: dataDockPrincipal}
	cases := []struct {
		name    string
		reply   *dpb.EdgeToRequester
		peer    string
		classes uint64
		nak     dpb.NakCode
	}{
		{name: "no-authority", reply: &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Nak{Nak: &dpb.Nak{Code: dpb.NakCode_NAK_CODE_UNAUTHORIZED}}}, nak: dpb.NakCode_NAK_CODE_UNAUTHORIZED},
		{name: "gone", reply: &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Nak{Nak: &dpb.Nak{Code: dpb.NakCode_NAK_CODE_TARGET_GONE}}}, nak: dpb.NakCode_NAK_CODE_TARGET_GONE},
		{name: "zero-id", reply: serviceReply(0, confirm)},
		{name: "no-confirm", reply: serviceReply(9)},
		{name: "wrong-principal", reply: serviceReply(9, &dpb.LaneTargetConfirm{Principal: "spiffe://zone-a.zone.example.org/node/n2/data-dock"})},
		{name: "generation-disclosed", reply: serviceReply(9, &dpb.LaneTargetConfirm{Principal: dataDockPrincipal, Gen: &commonpb.DockGen{Slot: 1}})},
		{name: "wrong-attachment", reply: serviceReply(9, confirm), peer: "spiffe://zone-a.zone.example.org/node/n2/data-dock", classes: wire.LaneClassStream},
		{name: "extra-class", reply: serviceReply(9, confirm), peer: dataDockPrincipal, classes: wire.LaneClassStream | wire.LaneClassFlow},
		{name: "unexpected-ack", reply: &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Ack{Ack: &dpb.Ack{}}}},
	}
	for _, transport := range edgeTransports {
		for _, tc := range cases {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(""))
				d, s := edge.open(nodeConfig(t, edge))
				result := startDataDockOpen(d, laneCtx(t), nil)
				st, _ := edgeServeVerb(laneCtx(t), t, s, tc.reply)
				if tc.peer != "" {
					if err := wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{
						LaneAttached: &dockpb.LaneAttached{LaneId: 9, PeerPrincipal: tc.peer, LaneClass: tc.classes},
					}}); err != nil {
						t.Fatal(err)
					}
				}
				_ = st.Close()
				got := <-result
				if got.err == nil || got.lane != nil {
					t.Fatalf("refusal returned lane: %v, %v", got.lane, got.err)
				}
				var nak NakError
				if tc.nak != 0 && (!errors.As(got.err, &nak) || nak.Code != tc.nak) {
					t.Fatalf("typed refusal lost: %v", got.err)
				}
				requireServiceFIN(t, st)
			})
		}
	}
}
