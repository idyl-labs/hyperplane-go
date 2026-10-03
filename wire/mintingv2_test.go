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
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	mintpb "github.com/idyl-labs/hyperplane-go/wire/mintingv2"
)

// TestMintingV2AtomicGenerations checks that a credential generation is
// accepted only as a complete unit: certificate chain, admission lease and
// paired trust snapshot together, with any renewal time inside the leaf's
// validity. A partial generation must refuse rather than install.
func TestMintingV2AtomicGenerations(t *testing.T) {
	lease := bytes.Repeat([]byte{0x55}, apb.MaxLeaseEnvelopeBytes)
	trustSnapshot, podLeafDER, podLeaf := testPodTrustPair(t)
	pod := &mintpb.PodCredentialGeneration{
		CertDer:       [][]byte{podLeafDER},
		LeaseEnvelope: lease,
		RenewAtUnixS:  uint64(trustTestNow.Add(6 * time.Hour).Unix()),
		TrustSnapshot: trustSnapshot,
	}
	// The leaf's not_before is backdated for clock skew to before its
	// paired trust snapshot was published. The snapshot was still published
	// before issuance, so this ordinary shape must validate without waiting
	// for the backdate interval to elapse.
	notBefore := uint64(podLeaf.NotBefore.Unix())
	notAfter := uint64(podLeaf.NotAfter.Unix())
	if err := mintpb.ValidatePodCredentialGeneration(pod, notBefore, notAfter); err != nil {
		t.Fatalf("honest pod generation refused: %v", err)
	}
	session := &mintpb.SessionCredentialGeneration{
		CertDer:       [][]byte{podLeafDER},
		LeaseEnvelope: lease,
		TrustSnapshot: trustSnapshot,
	}
	if err := mintpb.ValidateSessionCredentialGeneration(session); err != nil {
		t.Fatalf("honest session generation refused: %v", err)
	}
	missingSessionTrust := proto.Clone(session).(*mintpb.SessionCredentialGeneration)
	missingSessionTrust.TrustSnapshot = nil
	if err := mintpb.ValidateSessionCredentialGeneration(missingSessionTrust); err == nil {
		t.Fatal("session generation without paired trust must refuse")
	}

	for _, row := range []struct {
		name string
		mut  func(*mintpb.PodCredentialGeneration)
	}{
		{"missing chain", func(g *mintpb.PodCredentialGeneration) { g.CertDer = nil }},
		{"missing lease", func(g *mintpb.PodCredentialGeneration) { g.LeaseEnvelope = nil }},
		{"renewal before interval", func(g *mintpb.PodCredentialGeneration) { g.RenewAtUnixS = notBefore - 1 }},
		{"renewal at expiry", func(g *mintpb.PodCredentialGeneration) { g.RenewAtUnixS = notAfter }},
		{"missing trust snapshot", func(g *mintpb.PodCredentialGeneration) { g.TrustSnapshot = nil }},
		{"wrong trust purpose", func(g *mintpb.PodCredentialGeneration) { g.TrustSnapshot.Purpose = 1 }},
	} {
		got := proto.Clone(pod).(*mintpb.PodCredentialGeneration)
		row.mut(got)
		if err := mintpb.ValidatePodCredentialGeneration(got, notBefore, notAfter); err == nil {
			t.Errorf("%s must refuse", row.name)
		}
	}

	tooLarge := proto.Clone(pod).(*mintpb.PodCredentialGeneration)
	tooLarge.LeaseEnvelope = append(tooLarge.LeaseEnvelope, 0)
	if err := mintpb.ValidatePodCredentialGeneration(tooLarge, notBefore, notAfter); err == nil {
		t.Fatal("oversize lease must refuse")
	}
}

func TestMintingV2SessionRequestProfiles(t *testing.T) {
	base := &mintpb.MintSessionSvidRequest{
		CsrDer:               []byte{0x30, 0x01, 0x01},
		SessionId:            "session-1",
		SessionKind:          mpb.SessionKind_SESSION_KIND_EXEC,
		SessionLeg:           mpb.SessionLeg_SESSION_LEG_CLIENT,
		PodId:                "33333333-3333-3333-3333-333333333333",
		AssignmentGeneration: 7,
		ExpiresAtUnixS:       1_700_003_600,
	}
	if err := mintpb.ValidateMintSessionSvidRequest(base); err != nil {
		t.Fatalf("client request refused: %v", err)
	}
	proxy := proto.Clone(base).(*mintpb.MintSessionSvidRequest)
	proxy.SessionLeg = mpb.SessionLeg_SESSION_LEG_PROXY
	proxy.GrantId = "grant-1"
	if err := mintpb.ValidateMintSessionSvidRequest(proxy); err != nil {
		t.Fatalf("proxy request refused: %v", err)
	}

	clientGrant := proto.Clone(base).(*mintpb.MintSessionSvidRequest)
	clientGrant.GrantId = "grant-1"
	if err := mintpb.ValidateMintSessionSvidRequest(clientGrant); err == nil {
		t.Fatal("client leg with proxy grant must refuse")
	}
	proxyNoGrant := proto.Clone(proxy).(*mintpb.MintSessionSvidRequest)
	proxyNoGrant.GrantId = ""
	if err := mintpb.ValidateMintSessionSvidRequest(proxyNoGrant); err == nil {
		t.Fatal("proxy leg without grant must refuse")
	}
	unknownKind := proto.Clone(base).(*mintpb.MintSessionSvidRequest)
	unknownKind.SessionKind = mpb.SessionKind(99)
	if err := mintpb.ValidateMintSessionSvidRequest(unknownKind); err == nil {
		t.Fatal("unknown session kind must refuse")
	}
}
