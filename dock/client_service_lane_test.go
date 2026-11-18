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
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

const clientServicePrincipal = "spiffe://zone-a.zone.example.org/service/events"

func startClientServiceOpen(d *Dock, ctx context.Context, metadata []byte) <-chan serviceOpenResult {
	result := make(chan serviceOpenResult, 1)
	go func() {
		lane, err := d.OpenClientServiceLane(ctx, clientServicePrincipal, metadata)
		result <- serviceOpenResult{lane, err}
	}()
	return result
}

// Only an admitted dock/3 dock whose edge negotiated the client profile asks,
// and only for an exact canonical principal; anything else is refused before
// any transport is used.
func TestClientServiceLaneRefusesLocallyWithoutTheNegotiatedProfile(t *testing.T) {
	if lane, err := (&Dock{}).OpenClientServiceLane(laneCtx(t), clientServicePrincipal, nil); err == nil || lane != nil {
		t.Fatal("unadmitted dock opened a client service lane")
	}
	d, edge := newLaneDock(t)
	d.serviceLaneProfile = wire.ClientServiceLaneProfile
	if lane, err := d.OpenClientServiceLane(laneCtx(t), clientServicePrincipal, nil); err == nil || lane != nil {
		t.Fatal("dock/2 connection opened a client service lane")
	}
	d.node = true
	for _, profile := range []string{"", wire.NodeServiceLaneProfile, "future-profile/2"} {
		d.serviceLaneProfile = profile
		lane, err := d.OpenClientServiceLane(laneCtx(t), clientServicePrincipal, nil)
		var nak NakError
		if lane != nil || !errors.As(err, &nak) || nak.Code != dpb.NakCode_NAK_CODE_ADAPTER_MISMATCH {
			t.Fatalf("profile %q: %v, %v", profile, lane, err)
		}
	}
	d.serviceLaneProfile = wire.ClientServiceLaneProfile
	for _, principal := range []string{"", "https://zone-a.zone.example.org/service/events", clientServicePrincipal + "?x=1", clientServicePrincipal + "/"} {
		if lane, err := d.OpenClientServiceLane(laneCtx(t), principal, nil); err == nil || lane != nil {
			t.Fatalf("noncanonical target %q opened: %v, %v", principal, lane, err)
		}
	}
	if edge.conn.opens.Load() != 0 {
		t.Fatal("a refused client service lane used the transport")
	}
}

// A client service lane opens on one verb, attaches as one STREAM lane to the
// named principal, and carries a client-opened e2e-mtls stream with the
// application's header, on both transports.
func TestOpenClientServiceLaneOverBothTransports(t *testing.T) {
	header := []byte("computer-events/json-v1")
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(wire.ClientServiceLaneProfile))
			d, s := edge.open(nodeConfig(t, edge))
			if d.ServiceLaneProfile() != wire.ClientServiceLaneProfile {
				t.Fatalf("negotiated profile = %q", d.ServiceLaneProfile())
			}
			ctx, cancel := context.WithCancel(laneCtx(t))
			defer cancel()
			result := startClientServiceOpen(d, ctx, nil)
			st, verb := edgeServeVerb(laneCtx(t), t, s, serviceReply(5, &dpb.LaneTargetConfirm{Principal: clientServicePrincipal}))
			request := verb.GetOpenClientServiceLane()
			if request == nil || request.GetServicePrincipal() != clientServicePrincipal || len(request.GetMetadata()) != 0 {
				t.Fatalf("client service verb = %v", verb)
			}
			if err := wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{
				LaneAttached: &dockpb.LaneAttached{LaneId: 5, PeerPrincipal: clientServicePrincipal, LaneClass: wire.LaneClassStream},
			}}); err != nil {
				t.Fatal(err)
			}
			_ = st.Close()
			got := <-result
			if got.err != nil || got.lane.ID() != 5 || got.lane.Classes() != wire.LaneClassStream {
				t.Fatalf("client service lane = %v, %v", got.lane, got.err)
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
			if err != nil || h.LaneID != 5 || h.Class != wire.LaneStreamClassE2EMTLS || string(h.Header) != string(header) {
				t.Fatalf("stream header = %+v, %v", h, err)
			}
			_ = stream.Close()
			_ = peer.Close()
		})
	}
}

// Every malformed or mismatched answer is refused, and a typed edge refusal
// keeps its code.
func TestClientServiceLaneRefusalsOverBothTransports(t *testing.T) {
	confirm := &dpb.LaneTargetConfirm{Principal: clientServicePrincipal}
	nakReply := func(code dpb.NakCode) *dpb.EdgeToRequester {
		return &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Nak{Nak: &dpb.Nak{Code: code}}}
	}
	cases := []struct {
		name    string
		reply   *dpb.EdgeToRequester
		peer    string
		classes uint64
		nak     dpb.NakCode
	}{
		{name: "no-authority", reply: nakReply(dpb.NakCode_NAK_CODE_UNAUTHORIZED), nak: dpb.NakCode_NAK_CODE_UNAUTHORIZED},
		{name: "gone", reply: nakReply(dpb.NakCode_NAK_CODE_TARGET_GONE), nak: dpb.NakCode_NAK_CODE_TARGET_GONE},
		{name: "limit", reply: nakReply(dpb.NakCode_NAK_CODE_LANE_LIMIT), nak: dpb.NakCode_NAK_CODE_LANE_LIMIT},
		{name: "zero-id", reply: serviceReply(0, confirm)},
		{name: "no-confirm", reply: serviceReply(5)},
		{name: "wrong-principal", reply: serviceReply(5, &dpb.LaneTargetConfirm{Principal: "spiffe://zone-a.zone.example.org/service/other"})},
		{name: "generation-disclosed", reply: serviceReply(5, &dpb.LaneTargetConfirm{Principal: clientServicePrincipal, Gen: &commonpb.DockGen{Slot: 1}})},
		{name: "wrong-attachment", reply: serviceReply(5, confirm), peer: "spiffe://zone-a.zone.example.org/service/other", classes: wire.LaneClassStream},
		{name: "extra-class", reply: serviceReply(5, confirm), peer: clientServicePrincipal, classes: wire.LaneClassStream | wire.LaneClassFlow},
		{name: "unexpected-ack", reply: &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Ack{Ack: &dpb.Ack{}}}},
	}
	for _, transport := range edgeTransports {
		for _, tc := range cases {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(wire.ClientServiceLaneProfile))
				d, s := edge.open(nodeConfig(t, edge))
				result := startClientServiceOpen(d, laneCtx(t), nil)
				st, _ := edgeServeVerb(laneCtx(t), t, s, tc.reply)
				if tc.peer != "" {
					if err := wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{
						LaneAttached: &dockpb.LaneAttached{LaneId: 5, PeerPrincipal: tc.peer, LaneClass: tc.classes},
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

// A Service connection offers the client profile on dock/2 and opens only
// when the edge's welcome names that profile; it may then withdraw.
func TestServiceOffersTheClientProfileOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		for _, welcomed := range []string{"", wire.NodeServiceLaneProfile, wire.ClientServiceLaneProfile} {
			t.Run(transport+"/"+welcomed, func(t *testing.T) {
				edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(welcomed))
				cfg := edge.config()
				cfg.ServiceTargetProfile = wire.ClientServiceLaneProfile
				d, err := Open(laneCtx(t), cfg)
				if welcomed != wire.ClientServiceLaneProfile {
					if err == nil || d != nil {
						t.Fatalf("unnegotiated profile opened: %v, %v", d, err)
					}
					return
				}
				if err != nil || d.ServiceLaneProfile() != wire.ClientServiceLaneProfile {
					t.Fatalf("Open = %v, %v", d, err)
				}
				t.Cleanup(func() { _ = d.Abandon() })
				s := edge.session()
				result := make(chan error, 1)
				go func() { result <- d.WithdrawServiceTarget(laneCtx(t)) }()
				st, verb := edgeServeVerb(laneCtx(t), t, s, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Ack{Ack: &dpb.Ack{}}})
				if verb.GetWithdrawServiceTarget() == nil {
					t.Fatalf("withdraw verb = %v", verb)
				}
				_ = st.Close()
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}
