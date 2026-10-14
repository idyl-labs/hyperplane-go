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

package wire

import (
	"bytes"
	"encoding/hex"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
	dockv3pb "github.com/idyl-labs/hyperplane-go/wire/dockv3"
)

// These literal bytes pin field numbers and omission, independent of a
// round-trip encoder. Profile fields are additive to ordinary docking.
func TestServiceLaneWireGoldens(t *testing.T) {
	cases := []struct {
		name string
		msg  proto.Message
		hex  string
	}{
		{"ordinary-hello", &dockpb.ClientToEdge{Msg: &dockpb.ClientToEdge_Hello{Hello: &dockpb.DockHello{Contract: "dock/2"}}}, "0a080a06646f636b2f32"},
		{"service-offer", &dockpb.ClientToEdge{Msg: &dockpb.ClientToEdge_Hello{Hello: &dockpb.DockHello{Contract: "dock/2", ServiceTargetProfile: NodeServiceLaneProfile}}}, "0a1e0a06646f636b2f3222146e6f64652d736572766963652d6c616e65732f31"},
		{"ordinary-welcome-2", &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Welcome{Welcome: &dockpb.DockWelcome{KeepaliveMs: 20}}}, "0a021014"},
		{"ordinary-welcome-3", &dockv3pb.EdgeToClient{Msg: &dockv3pb.EdgeToClient_Welcome{Welcome: &dockv3pb.DockWelcome{KeepaliveMs: 20}}}, "0a021014"},
		{"profile-welcome-2", &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Welcome{Welcome: &dockpb.DockWelcome{KeepaliveMs: 20, ServiceLaneProfile: NodeServiceLaneProfile}}}, "0a1810141a146e6f64652d736572766963652d6c616e65732f31"},
		{"profile-welcome-3", &dockv3pb.EdgeToClient{Msg: &dockv3pb.EdgeToClient_Welcome{Welcome: &dockv3pb.DockWelcome{KeepaliveMs: 20, ServiceLaneProfile: NodeServiceLaneProfile}}}, "0a1810141a146e6f64652d736572766963652d6c616e65732f31"},
		{"ordinary-event", &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_SendEvent{SendEvent: &dpb.SendEvent{Locator: []byte("x"), Payload: []byte("y")}}}, "0a060a0178120179"},
		{"ordinary-rpc", &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_OpenRpc{OpenRpc: &dpb.OpenRpc{Locator: []byte("x"), Metadata: []byte("y")}}}, "12060a0178120179"},
		{"ordinary-lane", &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_OpenLane{OpenLane: &dpb.OpenLane{LaneClass: LaneClassStream}}}, "22021004"},
		{"service-lane", &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_OpenServiceLane{OpenServiceLane: &dpb.OpenServiceLane{ServicePrincipal: "spiffe://example.org/a", Metadata: []byte("x")}}}, "2a1b0a167370696666653a2f2f6578616d706c652e6f72672f61120178"},
		{"withdraw-service", &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_WithdrawServiceTarget{WithdrawServiceTarget: &dpb.WithdrawServiceTarget{}}}, "3200"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.hex)
			if err != nil {
				t.Fatal(err)
			}
			got, err := proto.MarshalOptions{Deterministic: true}.Marshal(tc.msg)
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("wire = %x, %v; want %x", got, err, want)
			}
		})
	}
	// Dock/3 field 4 remains its signed lease. The Service offer belongs only
	// to dock/2; it must never overwrite admission material or its proof.
	field := (&dockv3pb.DockHello{}).ProtoReflect().Descriptor().Fields().ByNumber(4)
	if field.Name() != "lease_envelope" || field.Kind() != protoreflect.BytesKind {
		t.Fatalf("dock/3 field 4 changed: %v", field)
	}
}

// Welcome is lenient on read. An unknown profile can be observed but does
// not bind to the supported service operation; an unrelated unknown field
// survives decode/re-encode without changing known fields.
func TestServiceWelcomeUnknownFieldsRemainLenient(t *testing.T) {
	raw := []byte{0x0a, 0x05, 0x10, 0x14, 0x98, 0x06, 0x01}
	var welcome dockpb.EdgeToClient
	if err := proto.Unmarshal(raw, &welcome); err != nil {
		t.Fatal(err)
	}
	if welcome.GetWelcome().GetKeepaliveMs() != 20 || welcome.GetWelcome().GetServiceLaneProfile() != "" {
		t.Fatalf("unknown field changed known fields: %v", &welcome)
	}
	got, err := proto.Marshal(&welcome)
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("unknown welcome field = %x, %v; want %x", got, err, raw)
	}
}
