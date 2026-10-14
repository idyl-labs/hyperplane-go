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
	"crypto/ed25519"
	"errors"
	"io"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire"
	commonpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
)

const servicePrincipal = "spiffe://example.org/service/a"

func serviceWelcome(profile string) func(*edgeSession) error {
	return func(s *edgeSession) error {
		return wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Welcome{
			Welcome: &dockpb.DockWelcome{Gen: edgeGen, KeepaliveMs: 20_000, ServiceLaneProfile: profile},
		}})
	}
}

// Profile negotiation is tested on real connections, including the refusal
// path: requesting a missing profile never retries an ordinary opening.
func TestServiceProfileNegotiationOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		for _, offered := range []bool{false, true} {
			for _, profile := range []string{"", wire.NodeServiceLaneProfile, "future-profile/2"} {
				t.Run(transport+"/"+profile+"/offer="+boolName(offered), func(t *testing.T) {
					edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(profile))
					cfg := edge.config()
					if offered {
						cfg.ServiceTargetProfile = wire.NodeServiceLaneProfile
					}
					d, err := Open(laneCtx(t), cfg)
					s := edge.session()
					var hello dockpb.ClientToEdge
					if err := proto.Unmarshal(s.hello, &hello); err != nil {
						t.Fatal(err)
					}
					if hello.GetHello().GetServiceTargetProfile() != cfg.ServiceTargetProfile {
						t.Fatalf("hello profile = %q", hello.GetHello().GetServiceTargetProfile())
					}
					if offered && profile != wire.NodeServiceLaneProfile {
						if err == nil || d != nil {
							t.Fatalf("unavailable profile opened: %v, %v", d, err)
						}
						select {
						case <-s.done():
						case <-laneCtx(t).Done():
							t.Fatal("refused opening retained its connection")
						}
					} else {
						if err != nil || d.ServiceLaneProfile() != profile {
							t.Fatalf("Open = %v, %v", d, err)
						}
						t.Cleanup(func() { _ = d.Abandon() })
					}
					if edge.accepted.Load() != 1 {
						t.Fatalf("opening retried: %d connections", edge.accepted.Load())
					}
				})
			}
		}
	}
}

func boolName(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func TestInvalidServiceOfferDoesNotDial(t *testing.T) {
	pki := newTestPKI(t)
	endpoint, accepted := countingListener(t)
	for _, node := range []bool{false, true} {
		cfg := pki.clientConfig()
		cfg.Endpoint, cfg.ForceFallback = endpoint, true
		cfg.ServiceTargetProfile = "future-profile/2"
		if node {
			cfg.ServiceTargetProfile = wire.NodeServiceLaneProfile
			cfg.Admission = &DemandAdmission{
				LeaseEnvelope: testNodeLease(t, time.Now()), Signer: pki.clientCert.PrivateKey.(ed25519.PrivateKey),
			}
		}
		if d, err := Open(laneCtx(t), cfg); err == nil || d != nil {
			t.Fatalf("invalid service offer opened: %v, %v", d, err)
		}
	}
	if accepted.Load() != 0 {
		t.Fatal("invalid service offer dialed")
	}
}

func TestServiceOperationsRefuseLocallyWithoutNegotiatedProfile(t *testing.T) {
	if lane, err := (&Dock{}).OpenServiceLane(laneCtx(t), servicePrincipal, nil); err == nil || lane != nil {
		t.Fatal("unadmitted dock opened service lane")
	}
	if err := (&Dock{}).WithdrawServiceTarget(laneCtx(t)); err == nil {
		t.Fatal("unadmitted dock withdrew service target")
	}
	for _, profile := range []string{"", "future-profile/2"} {
		d, edge := newLaneDock(t)
		d.serviceLaneProfile, d.serviceTarget = profile, true
		_, err := d.OpenServiceLane(laneCtx(t), servicePrincipal, nil)
		var nak NakError
		if !errors.As(err, &nak) || nak.Code != dpb.NakCode_NAK_CODE_ADAPTER_MISMATCH {
			t.Fatalf("missing profile: %v", err)
		}
		err = d.WithdrawServiceTarget(laneCtx(t))
		if !errors.As(err, &nak) || nak.Code != dpb.NakCode_NAK_CODE_ADAPTER_MISMATCH {
			t.Fatalf("missing withdrawal profile: %v", err)
		}
		if edge.conn.opens.Load() != 0 {
			t.Fatal("unavailable service operation opened a delivery stream")
		}
	}
	d, edge := newLaneDock(t)
	d.serviceLaneProfile = wire.NodeServiceLaneProfile
	for _, principal := range []string{"", "https://example.org/service", "spiffe://example.org/service/a?token=opaque"} {
		if lane, err := d.OpenServiceLane(laneCtx(t), principal, nil); err == nil || lane != nil {
			t.Fatalf("noncanonical selector opened: %v, %v", lane, err)
		}
	}
	if err := d.WithdrawServiceTarget(laneCtx(t)); err == nil {
		t.Fatal("unoffered connection withdrew service target")
	}
	if edge.conn.opens.Load() != 0 {
		t.Fatal("invalid selector or opt-in used transport")
	}
}

type serviceOpenResult struct {
	lane *Lane
	err  error
}

func startServiceOpen(d *Dock, ctx context.Context, metadata []byte) <-chan serviceOpenResult {
	result := make(chan serviceOpenResult, 1)
	go func() {
		lane, err := d.OpenServiceLane(ctx, servicePrincipal, metadata)
		result <- serviceOpenResult{lane, err}
	}()
	return result
}

func serviceReply(id uint64, confirms ...*dpb.LaneTargetConfirm) *dpb.EdgeToRequester {
	return &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_LaneOpened{
		LaneOpened: &dpb.LaneOpened{LaneId: id, TargetConfirms: confirms},
	}}
}

func requireServiceFIN(t *testing.T, st edgeBidi) {
	t.Helper()
	if rest, err := io.ReadAll(st); err != nil || len(rest) != 0 {
		t.Fatalf("one-shot FIN = %x, %v", rest, err)
	}
}

func TestOpenServiceLaneOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(wire.NodeServiceLaneProfile))
			cfg := edge.config()
			cfg.Admission = &DemandAdmission{
				LeaseEnvelope: testNodeLease(t, time.Now()), Signer: edge.pki.clientCert.PrivateKey.(ed25519.PrivateKey),
			}
			d, s := edge.open(cfg)
			ctx, cancel := context.WithCancel(laneCtx(t))
			defer cancel()
			result := startServiceOpen(d, ctx, []byte("opaque"))
			st, verb := edgeServeVerb(laneCtx(t), t, s, serviceReply(7, &dpb.LaneTargetConfirm{Principal: servicePrincipal}))
			request := verb.GetOpenServiceLane()
			if request == nil || request.GetServicePrincipal() != servicePrincipal || string(request.GetMetadata()) != "opaque" {
				t.Fatalf("service verb = %v", verb)
			}
			if err := wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{
				LaneAttached: &dockpb.LaneAttached{LaneId: 7, PeerPrincipal: servicePrincipal, LaneClass: wire.LaneClassStream},
			}}); err != nil {
				t.Fatal(err)
			}
			_ = st.Close()
			got := <-result
			if got.err != nil || got.lane.ID() != 7 || got.lane.Classes() != wire.LaneClassStream {
				t.Fatalf("service lane = %v, %v", got.lane, got.err)
			}
			requireServiceFIN(t, st)
			cancel()
			select {
			case <-got.lane.Closed():
				t.Fatal("setup cancellation closed the established lane")
			default:
			}
			claimCtx, claimCancel := context.WithCancel(laneCtx(t))
			claimCancel()
			if lane, err := d.AcceptLane(claimCtx); !errors.Is(err, context.Canceled) || lane != nil {
				t.Fatalf("opened lane was not claimed: %v, %v", lane, err)
			}
			stream, err := got.lane.OpenStream(laneCtx(t), wire.LaneStreamClassE2EMTLS, []byte("protocol"))
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
			if err != nil || h.LaneID != 7 || h.Class != wire.LaneStreamClassE2EMTLS || string(h.Header) != "protocol" {
				t.Fatalf("established stream header = %+v, %v", h, err)
			}
			_ = stream.Close()
			_ = peer.Close()
			if _, err := io.ReadAll(stream); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServiceLaneRefusalsOverBothTransports(t *testing.T) {
	confirm := &dpb.LaneTargetConfirm{Principal: servicePrincipal}
	cases := []struct {
		name    string
		reply   *dpb.EdgeToRequester
		peer    string
		classes uint64
		nak     dpb.NakCode
	}{
		{name: "no-authority", reply: &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Nak{Nak: &dpb.Nak{Code: dpb.NakCode_NAK_CODE_UNAUTHORIZED}}}, nak: dpb.NakCode_NAK_CODE_UNAUTHORIZED},
		{name: "zero-id", reply: serviceReply(0, confirm)},
		{name: "no-confirm", reply: serviceReply(7)},
		{name: "two-confirms", reply: serviceReply(7, confirm, confirm)},
		{name: "wrong-principal", reply: serviceReply(7, &dpb.LaneTargetConfirm{Principal: "spiffe://example.org/service/b"})},
		{name: "generation-disclosed", reply: serviceReply(7, &dpb.LaneTargetConfirm{Principal: servicePrincipal, Gen: &commonpb.DockGen{Slot: 1}})},
		{name: "wrong-attachment", reply: serviceReply(7, confirm), peer: "spiffe://example.org/service/b", classes: wire.LaneClassStream},
		{name: "extra-class", reply: serviceReply(7, confirm), peer: servicePrincipal, classes: wire.LaneClassStream | wire.LaneClassFlow},
		{name: "unexpected-ack", reply: &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Ack{Ack: &dpb.Ack{}}}},
	}
	for _, transport := range edgeTransports {
		for _, tc := range cases {
			t.Run(transport+"/"+tc.name, func(t *testing.T) {
				edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(wire.NodeServiceLaneProfile))
				d, s := edge.open(edge.config())
				result := startServiceOpen(d, laneCtx(t), nil)
				st, _ := edgeServeVerb(laneCtx(t), t, s, tc.reply)
				if tc.peer != "" {
					if err := wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{
						LaneAttached: &dockpb.LaneAttached{LaneId: 7, PeerPrincipal: tc.peer, LaneClass: tc.classes},
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

func TestServiceWithdrawalOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(wire.NodeServiceLaneProfile))
			cfg := edge.config()
			cfg.ServiceTargetProfile = wire.NodeServiceLaneProfile
			d, s := edge.open(cfg)
			if err := wire.WriteFrame(s.control, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_LaneAttached{
				LaneAttached: &dockpb.LaneAttached{LaneId: 7, PeerPrincipal: "spiffe://example.org/node/a", LaneClass: wire.LaneClassStream},
			}}); err != nil {
				t.Fatal(err)
			}
			lane, err := d.AcceptLane(laneCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 2; i++ {
				result := make(chan error, 1)
				go func() { result <- d.WithdrawServiceTarget(laneCtx(t)) }()
				st, verb := edgeServeVerb(laneCtx(t), t, s, &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Ack{Ack: &dpb.Ack{}}})
				if verb.GetWithdrawServiceTarget() == nil {
					t.Fatalf("withdrawal verb = %v", verb)
				}
				_ = st.Close()
				if err := <-result; err != nil {
					t.Fatal(err)
				}
				requireServiceFIN(t, st)
				select {
				case <-lane.Closed():
					t.Fatal("withdrawal closed an established lane")
				case <-d.Context().Done():
					t.Fatal("withdrawal closed the dock")
				default:
				}
			}
		})
	}
}

func TestServiceWithdrawalRefusalOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		for _, refused := range []bool{false, true} {
			t.Run(transport+"/nak="+boolName(refused), func(t *testing.T) {
				edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(wire.NodeServiceLaneProfile))
				cfg := edge.config()
				cfg.ServiceTargetProfile = wire.NodeServiceLaneProfile
				d, s := edge.open(cfg)
				ctx := laneCtx(t)
				result := make(chan error, 1)
				go func() { result <- d.WithdrawServiceTarget(ctx) }()
				reply := &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_RpcOpened{RpcOpened: &dpb.RpcOpened{}}}
				if refused {
					reply = &dpb.EdgeToRequester{Msg: &dpb.EdgeToRequester_Nak{Nak: &dpb.Nak{Code: dpb.NakCode_NAK_CODE_UNAUTHORIZED}}}
				}
				st, _ := edgeServeVerb(ctx, t, s, reply)
				_ = st.Close()
				err := <-result
				var nak NakError
				if err == nil || (refused && (!errors.As(err, &nak) || nak.Code != dpb.NakCode_NAK_CODE_UNAUTHORIZED)) {
					t.Fatalf("withdrawal refusal = %v", err)
				}
				requireServiceFIN(t, st)
			})
		}
	}
}

func TestServiceMetadataUsesExistingFrameCapOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		t.Run(transport, func(t *testing.T) {
			edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(wire.NodeServiceLaneProfile))
			d, s := edge.open(edge.config())
			result := startServiceOpen(d, laneCtx(t), make([]byte, wire.DefaultMaxFrame))
			st, err := s.acceptStream(laneCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			var kind [1]byte
			if _, err := io.ReadFull(st, kind[:]); err != nil || kind[0] != wire.StreamKindDelivery {
				t.Fatalf("delivery kind = %x, %v", kind, err)
			}
			_ = st.Close()
			got := <-result
			if !errors.Is(got.err, wire.ErrFrameTooLarge) || got.lane != nil {
				t.Fatalf("oversize metadata = %v, %v", got.lane, got.err)
			}
			requireServiceFIN(t, st)
		})
	}
}

// Cancel both before the reply and while waiting for attachment. The request
// is reset promptly in both directions without ending the containing dock.
func TestServiceSetupCancellationOverBothTransports(t *testing.T) {
	for _, transport := range edgeTransports {
		for _, attachedReply := range []bool{false, true} {
			t.Run(transport+"/replied="+boolName(attachedReply), func(t *testing.T) {
				edge := newScriptedEdge(t, newTestPKI(t), transport, serviceWelcome(wire.NodeServiceLaneProfile))
				d, s := edge.open(edge.config())
				ctx, cancel := context.WithCancel(laneCtx(t))
				defer cancel()
				result := startServiceOpen(d, ctx, nil)
				st, err := s.acceptStream(laneCtx(t))
				if err != nil {
					t.Fatal(err)
				}
				var kind [1]byte
				if _, err := io.ReadFull(st, kind[:]); err != nil || kind[0] != wire.StreamKindDelivery {
					t.Fatalf("delivery kind = %x, %v", kind, err)
				}
				var verb dpb.RequesterToEdge
				if err := wire.ReadFrame(st, &verb, 0); err != nil || verb.GetOpenServiceLane() == nil {
					t.Fatalf("service verb = %v, %v", &verb, err)
				}
				if attachedReply {
					if err := wire.WriteFrame(st, serviceReply(7, &dpb.LaneTargetConfirm{Principal: servicePrincipal})); err != nil {
						t.Fatal(err)
					}
				}
				cancel()
				got := <-result
				if !errors.Is(got.err, context.Canceled) || got.lane != nil {
					t.Fatalf("canceled setup = %v, %v", got.lane, got.err)
				}
				if code, err := writeUntilReset(laneCtx(t), st); err != nil || code != wire.DockCodeProtocol {
					t.Fatalf("canceled write reset = %#x, %v", code, err)
				}
				if code, err := readUntilReset(st); err != nil || code != wire.DockCodeProtocol {
					t.Fatalf("canceled read reset = %#x, %v", code, err)
				}
				select {
				case <-d.Context().Done():
					t.Fatal("one-shot cancellation ended the dock")
				default:
				}
			})
		}
	}
}
