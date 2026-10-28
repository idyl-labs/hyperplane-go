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

package wire_test

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
)

const (
	clientThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	clientInstance   = "01954e20-7540-7ec4-93ec-14f783e6ab50"
	clientPrincipal  = "spiffe://z1.zone.example.com/account/acct-1/client/" + clientThumbprint + "/instance/" + clientInstance
)

// clientLeasePayload is one complete client lease: a six-segment data-plane
// principal naming its Account, key thumbprint and instance, bound to its
// Account and to nothing else (no Subnet, Node, Pod, session or share).
func clientLeasePayload() *apb.ZoneAdmissionLeasePayload {
	return &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              []byte("client-lease-001"),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_DATA,
		Principal:            clientPrincipal,
		SubjectSpkiSha256:    bytes.Repeat([]byte{0x55}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_CLIENT,
		OwnerScope:           "account/acct-1",
		AccountId:            "acct-1",
		AdapterClasses:       wire.LaneClassStream,
		LaneClassCeiling:     wire.LaneClassStream,
		PolicyProfile:        "client-default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       1_700_000_000,
		IssuedAtUnixS:        1_700_000_060,
		NotAfterUnixS:        1_700_003_660,
	}
}

// A client lease binds its principal's Account, key thumbprint and instance,
// names the data plane only, carries no fact of another kind, lives at most
// an hour, and ends with its SVID.
func TestZoneAdmissionLeaseClientProfile(t *testing.T) {
	payload := clientLeasePayload()
	if err := wire.ValidateZoneAdmissionLeasePayload(payload, payload.IssuedAtUnixS); err != nil {
		t.Fatalf("complete client lease refused: %v", err)
	}
	peer := wire.LeasePeer{
		Principal: payload.Principal, SubjectSPKISHA256: payload.SubjectSpkiSha256,
		Zone: payload.Zone, FabricPlane: payload.FabricPlane, EndpointKind: payload.EndpointKind,
		SVIDNotAfterUnixS: payload.NotAfterUnixS,
	}
	if err := wire.ValidateZoneAdmissionLeaseBinding(payload, peer); err != nil {
		t.Fatalf("client bound to its SVID refused: %v", err)
	}
	peer.SVIDNotAfterUnixS++
	if err := wire.ValidateZoneAdmissionLeaseBinding(payload, peer); err == nil {
		t.Fatal("client not_after differing from the SVID must refuse")
	}

	prefix := "spiffe://z1.zone.example.com/account/acct-1/client/"
	for name, mutate := range map[string]func(*apb.ZoneAdmissionLeasePayload){
		"missing account":     func(p *apb.ZoneAdmissionLeasePayload) { p.AccountId = "" },
		"account mismatch":    func(p *apb.ZoneAdmissionLeasePayload) { p.AccountId = "acct-2" },
		"missing owner scope": func(p *apb.ZoneAdmissionLeasePayload) { p.OwnerScope = "" },
		"control plane":       func(p *apb.ZoneAdmissionLeasePayload) { p.FabricPlane = mpb.Plane_PLANE_CONTROL },
		"extra segment":       func(p *apb.ZoneAdmissionLeasePayload) { p.Principal += "/x" },
		"short thumbprint":    func(p *apb.ZoneAdmissionLeasePayload) { p.Principal = prefix + "abc/instance/" + clientInstance },
		"uppercase instance": func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = prefix + clientThumbprint + "/instance/01954E20-7540-7EC4-93EC-14F783E6AB50"
		},
		"wrong keyword": func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = "spiffe://z1.zone.example.com/account/acct-1/clients/" + clientThumbprint + "/instance/" + clientInstance
		},
		"network form": func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = "spiffe://example.com/account/acct-1/client/" + clientThumbprint + "/instance/" + clientInstance
		},
		"subnet":  func(p *apb.ZoneAdmissionLeasePayload) { p.SubnetId = "subnet-1" },
		"node":    func(p *apb.ZoneAdmissionLeasePayload) { p.NodeId = "node-1" },
		"pod":     func(p *apb.ZoneAdmissionLeasePayload) { p.PodId = "pod-1" },
		"session": func(p *apb.ZoneAdmissionLeasePayload) { p.SessionId = "session-1" },
		"share":   func(p *apb.ZoneAdmissionLeasePayload) { p.ShareId = "shr_abc123" },
		"node admission": func(p *apb.ZoneAdmissionLeasePayload) {
			p.NodeAdmission = apb.NodeAdmission_NODE_ADMISSION_PROVIDER
		},
		"over one hour": func(p *apb.ZoneAdmissionLeasePayload) { p.NotAfterUnixS = p.IssuedAtUnixS + 3_601 },
	} {
		got := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
		mutate(got)
		if err := wire.ValidateZoneAdmissionLeasePayload(got, got.GetIssuedAtUnixS()); err == nil {
			t.Errorf("client lease with %s must refuse", name)
		}
	}
}
