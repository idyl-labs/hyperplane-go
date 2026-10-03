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

package svidtest_test

import (
	"bytes"
	"fmt"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/svidtest"
)

// ExampleAuthority_IssueAdmissionSigner mints a test CA on a fixed clock,
// issues a control-plane admission signer beneath it, signs a node lease,
// and verifies the lease against the CA's bundle as an edge would.
func ExampleAuthority_IssueAdmissionSigner() {
	now := time.Unix(1_700_000_060, 0).UTC()
	authority, err := svidtest.NewAuthority("zone-a.zone.example.com",
		svidtest.WithClock(func() time.Time { return now }))
	if err != nil {
		panic(err)
	}
	signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_CONTROL)
	if err != nil {
		panic(err)
	}
	fmt.Println("signer:", signer.URI)
	fmt.Println("chain length:", len(signer.ChainDER))
	fmt.Println("lifetime:", signer.Leaf.NotAfter.Sub(signer.Leaf.NotBefore))

	notBefore := uint64(now.Unix()) - 60
	envelope, err := signer.SignLease(&apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              bytes.Repeat([]byte{1}, apb.LeaseIDBytes),
		Zone:                 "zone-a",
		FabricPlane:          mpb.Plane_PLANE_CONTROL,
		Principal:            "spiffe://zone-a.zone.example.com/subnet/subnet-a/node/node-a",
		SubjectSpkiSha256:    bytes.Repeat([]byte{2}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_NODE,
		SubnetId:             "subnet-a",
		OwnerScope:           "node:node-a",
		NodeId:               "node-a",
		AdapterClasses:       1,
		PolicyProfile:        "default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       notBefore,
		IssuedAtUnixS:        notBefore + 60,
		NotAfterUnixS:        notBefore + 3600,
		NodeAdmission:        apb.NodeAdmission_NODE_ADMISSION_PROVIDER,
	})
	if err != nil {
		panic(err)
	}

	parsed, payload, err := wire.ParseZoneAdmissionLease(envelope, uint64(now.Unix()))
	if err != nil {
		panic(err)
	}
	facts, err := wire.VerifyZoneAdmissionLeaseSigner(parsed, authority.Bundle(), signer.URI, nil, now)
	if err != nil {
		panic(err)
	}
	fmt.Println("admitted node:", payload.GetNodeId(), "signed by:", facts.URI)
	// Output:
	// signer: spiffe://zone-a.zone.example.com/service/admission-signer/control
	// chain length: 1
	// lifetime: 12h1m0s
	// admitted node: node-a signed by: spiffe://zone-a.zone.example.com/service/admission-signer/control
}
