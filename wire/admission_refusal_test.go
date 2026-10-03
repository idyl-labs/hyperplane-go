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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv3"
	"github.com/idyl-labs/hyperplane-go/wire/svidtest"
)

// refusalNodePayload is one complete node lease valid at its issued_at.
func refusalNodePayload() *apb.ZoneAdmissionLeasePayload {
	return &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              bytes.Repeat([]byte{1}, apb.LeaseIDBytes),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_CONTROL,
		Principal:            "spiffe://z1.zone.example.com/subnet/subnet-1/node/node-a",
		SubjectSpkiSha256:    bytes.Repeat([]byte{2}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_NODE,
		SubnetId:             "subnet-1",
		OwnerScope:           "node:node-a",
		NodeId:               "node-a",
		AdapterClasses:       1,
		PolicyProfile:        "dynamic-default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       1_700_000_000,
		IssuedAtUnixS:        1_700_000_060,
		NotAfterUnixS:        1_700_003_600,
		NodeAdmission:        apb.NodeAdmission_NODE_ADMISSION_PROVIDER,
	}
}

// refusalSessionPayload is one complete client-leg exec session lease
// valid at its issued_at.
func refusalSessionPayload() *apb.ZoneAdmissionLeasePayload {
	podID := "33333333-3333-3333-3333-333333333333"
	return &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              []byte("fedcba9876543210"),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_DATA,
		Principal:            "spiffe://z1.zone.example.com/subnet/subnet-1/account/acct-1/namespace/11111111-1111-1111-1111-111111111111/workload/22222222-2222-2222-2222-222222222222/pod/" + podID + "/pod-instance/" + podID + ".7/session/exec/session-1/leg/client",
		SubjectSpkiSha256:    bytes.Repeat([]byte{0x33}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_SESSION,
		SubnetId:             "subnet-1",
		OwnerScope:           "workload-session",
		AccountId:            "acct-1",
		NamespaceId:          "11111111-1111-1111-1111-111111111111",
		WorkloadId:           "22222222-2222-2222-2222-222222222222",
		NodeId:               "node-a",
		PodId:                podID,
		PodInstanceId:        podID + ".7",
		AssignmentGeneration: 7,
		SessionId:            "session-1",
		SessionKind:          mpb.SessionKind_SESSION_KIND_EXEC,
		SessionLeg:           mpb.SessionLeg_SESSION_LEG_CLIENT,
		AdapterClasses:       wire.LaneClassStream | wire.LaneClassSpliceLeg,
		LaneClassCeiling:     wire.LaneClassStream | wire.LaneClassSpliceLeg,
		PolicyProfile:        "session-default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       1_700_000_000,
		IssuedAtUnixS:        1_700_000_060,
		NotAfterUnixS:        1_700_003_600,
	}
}

type payloadMutation struct {
	name   string
	mutate func(*apb.ZoneAdmissionLeasePayload)
}

// assertPayloadRefusals applies each mutation to a fresh copy of base and
// requires ValidateZoneAdmissionLeasePayload to refuse it with
// ErrAdmissionMalformed at the payload's own issued_at.
func assertPayloadRefusals(t *testing.T, base *apb.ZoneAdmissionLeasePayload, rows []payloadMutation) {
	t.Helper()
	if err := wire.ValidateZoneAdmissionLeasePayload(base, base.GetIssuedAtUnixS()); err != nil {
		t.Fatalf("base payload refused: %v", err)
	}
	for _, row := range rows {
		got := proto.Clone(base).(*apb.ZoneAdmissionLeasePayload)
		row.mutate(got)
		if err := wire.ValidateZoneAdmissionLeasePayload(got, got.GetIssuedAtUnixS()); !errors.Is(err, wire.ErrAdmissionMalformed) {
			t.Errorf("%s: err = %v, want ErrAdmissionMalformed", row.name, err)
		}
	}
}

// TestValidateZoneAdmissionLeasePayloadRefusesEnvelopeFields checks the
// kind-independent payload vocabulary: every bounded field, mask and time
// relation refuses as malformed, so no out-of-profile payload reaches the
// kind-specific checks.
func TestValidateZoneAdmissionLeasePayloadRefusesEnvelopeFields(t *testing.T) {
	assertPayloadRefusals(t, goldenPodPayload(), []payloadMutation{
		{"wrong version", func(p *apb.ZoneAdmissionLeasePayload) { p.Version = apb.PayloadVersion + 1 }},
		{"short lease id", func(p *apb.ZoneAdmissionLeasePayload) { p.LeaseId = p.LeaseId[:apb.LeaseIDBytes-1] }},
		{"empty zone", func(p *apb.ZoneAdmissionLeasePayload) { p.Zone = "" }},
		{"zone over the cap", func(p *apb.ZoneAdmissionLeasePayload) { p.Zone = strings.Repeat("z", apb.MaxZoneBytes+1) }},
		{"uppercase zone", func(p *apb.ZoneAdmissionLeasePayload) { p.Zone = "Z1" }},
		{"zone with leading hyphen", func(p *apb.ZoneAdmissionLeasePayload) { p.Zone = "-z1" }},
		{"zone with trailing hyphen", func(p *apb.ZoneAdmissionLeasePayload) { p.Zone = "z1-" }},
		{"unspecified plane", func(p *apb.ZoneAdmissionLeasePayload) { p.FabricPlane = mpb.Plane_PLANE_UNSPECIFIED }},
		{"principal over the cap", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal += strings.Repeat("x", apb.MaxPrincipalBytes)
		}},
		{"principal with surrounding space", func(p *apb.ZoneAdmissionLeasePayload) { p.Principal += " " }},
		{"principal with NUL", func(p *apb.ZoneAdmissionLeasePayload) { p.Principal += "\x00" }},
		{"principal invalid UTF-8", func(p *apb.ZoneAdmissionLeasePayload) { p.Principal += "\xff" }},
		{"short subject digest", func(p *apb.ZoneAdmissionLeasePayload) { p.SubjectSpkiSha256 = p.SubjectSpkiSha256[:31] }},
		{"unspecified kind", func(p *apb.ZoneAdmissionLeasePayload) { p.EndpointKind = mpb.EndpointKind_ENDPOINT_KIND_UNSPECIFIED }},
		{"identifier over the cap", func(p *apb.ZoneAdmissionLeasePayload) {
			p.OwnerScope = strings.Repeat("o", apb.MaxIdentifierBytes+1)
		}},
		{"identifier with surrounding space", func(p *apb.ZoneAdmissionLeasePayload) { p.NodeId = " node-a" }},
		{"uppercase namespace UUID", func(p *apb.ZoneAdmissionLeasePayload) {
			p.NamespaceId = "ABCDEF00-1111-1111-1111-111111111111"
		}},
		{"namespace UUID with misplaced hyphen", func(p *apb.ZoneAdmissionLeasePayload) {
			p.NamespaceId = "1111111-11111-1111-1111-111111111111"
		}},
		{"empty adapter mask", func(p *apb.ZoneAdmissionLeasePayload) { p.AdapterClasses, p.LaneClassCeiling = 0, 0 }},
		{"unassigned adapter bit", func(p *apb.ZoneAdmissionLeasePayload) { p.AdapterClasses |= 1 << 7 }},
		{"lane class not a lane bit", func(p *apb.ZoneAdmissionLeasePayload) {
			p.AdapterClasses |= 1
			p.LaneClassCeiling |= 1
		}},
		{"lane ceiling beyond adapters", func(p *apb.ZoneAdmissionLeasePayload) {
			p.LaneClassCeiling |= wire.LaneClassIngressTarget
		}},
		{"empty policy profile", func(p *apb.ZoneAdmissionLeasePayload) { p.PolicyProfile = "" }},
		{"policy profile over the cap", func(p *apb.ZoneAdmissionLeasePayload) {
			p.PolicyProfile = strings.Repeat("p", apb.MaxPolicyProfileBytes+1)
		}},
		{"policy version zero", func(p *apb.ZoneAdmissionLeasePayload) { p.PolicyProfileVersion = 0 }},
		{"not_before zero", func(p *apb.ZoneAdmissionLeasePayload) { p.NotBeforeUnixS = 0 }},
		{"not_after zero", func(p *apb.ZoneAdmissionLeasePayload) { p.NotAfterUnixS = 0 }},
		{"not_before at the u64 limit", func(p *apb.ZoneAdmissionLeasePayload) {
			p.NotBeforeUnixS = math.MaxUint64
			p.IssuedAtUnixS = math.MaxUint64
			p.NotAfterUnixS = math.MaxUint64
		}},
		{"issued_at at not_after", func(p *apb.ZoneAdmissionLeasePayload) { p.NotAfterUnixS = p.IssuedAtUnixS }},
		{"unknown field", func(p *apb.ZoneAdmissionLeasePayload) { p.ProtoReflect().SetUnknown(unknownVarintField) }},
	})
	if err := wire.ValidateZoneAdmissionLeasePayload(nil, 1); !errors.Is(err, wire.ErrAdmissionMalformed) {
		t.Fatalf("nil payload: err = %v, want ErrAdmissionMalformed", err)
	}
}

// TestValidateZoneAdmissionLeasePayloadClockClasses checks that the clock
// judgments use their own classes, so a caller can tell an early or late
// lease from a malformed one: valid from not_before inclusive to not_after
// exclusive, with no grace on either side.
func TestValidateZoneAdmissionLeasePayloadClockClasses(t *testing.T) {
	p := goldenPodPayload()
	if err := wire.ValidateZoneAdmissionLeasePayload(p, p.GetNotBeforeUnixS()-1); !errors.Is(err, wire.ErrAdmissionNotYetValid) {
		t.Fatalf("one second before not_before: err = %v, want ErrAdmissionNotYetValid", err)
	}
	if err := wire.ValidateZoneAdmissionLeasePayload(p, p.GetNotAfterUnixS()-1); err != nil {
		t.Fatalf("one second before not_after refused: %v", err)
	}
	if err := wire.ValidateZoneAdmissionLeasePayload(p, p.GetNotAfterUnixS()); !errors.Is(err, wire.ErrAdmissionExpired) {
		t.Fatalf("at not_after: err = %v, want ErrAdmissionExpired", err)
	}
}

// TestValidateZoneAdmissionLeasePayloadRefusesMalformedPrincipals checks
// the SPIFFE principal grammar shared by every kind: exact round-trip form,
// spiffe scheme only, no user, port, query, fragment or escaped path, a
// trust domain under the lease's zone, and no empty or padded segment.
func TestValidateZoneAdmissionLeasePayloadRefusesMalformedPrincipals(t *testing.T) {
	const path = "/subnet/subnet-1/node/node-a"
	rows := []payloadMutation{}
	for name, principal := range map[string]string{
		"unparseable":              "spiffe://z1.zone.example.com/%zz",
		"not round-trip exact":     "SPIFFE://z1.zone.example.com" + path,
		"opaque":                   "spiffe:z1.zone.example.com" + path,
		"user info":                "spiffe://user@z1.zone.example.com" + path,
		"port":                     "spiffe://z1.zone.example.com:443" + path,
		"query":                    "spiffe://z1.zone.example.com" + path + "?q=1",
		"empty query":              "spiffe://z1.zone.example.com" + path + "?",
		"fragment":                 "spiffe://z1.zone.example.com" + path + "#f",
		"escaped path":             "spiffe://z1.zone.example.com/subnet/subnet%2F1/node/node-a",
		"bare zone trust domain":   "spiffe://z1.zone." + path,
		"other zone trust domain":  "spiffe://z2.zone.example.com" + path,
		"no path":                  "spiffe://z1.zone.example.com",
		"trailing slash":           "spiffe://z1.zone.example.com" + path + "/",
		"empty segment":            "spiffe://z1.zone.example.com/subnet//node/node-a",
		"node segment count":       "spiffe://z1.zone.example.com" + path + "/extra",
		"node keyword":             "spiffe://z1.zone.example.com/subnet/subnet-1/nodes/node-a",
		"node identifier mismatch": "spiffe://z1.zone.example.com/subnet/subnet-1/node/node-b",
	} {
		rows = append(rows, payloadMutation{name, func(p *apb.ZoneAdmissionLeasePayload) { p.Principal = principal }})
	}
	assertPayloadRefusals(t, refusalNodePayload(), rows)
}

// TestValidateZoneAdmissionLeasePayloadNodeProfile checks the node leg:
// subnet, owner scope and node identity required, the provider admission
// fact present, a signed interval of at most 24 hours, and no field that
// belongs to another endpoint kind.
func TestValidateZoneAdmissionLeasePayloadNodeProfile(t *testing.T) {
	assertPayloadRefusals(t, refusalNodePayload(), []payloadMutation{
		{"missing subnet", func(p *apb.ZoneAdmissionLeasePayload) { p.SubnetId = "" }},
		{"missing owner scope", func(p *apb.ZoneAdmissionLeasePayload) { p.OwnerScope = "" }},
		{"missing node", func(p *apb.ZoneAdmissionLeasePayload) { p.NodeId = "" }},
		{"no provider admission", func(p *apb.ZoneAdmissionLeasePayload) {
			p.NodeAdmission = apb.NodeAdmission_NODE_ADMISSION_UNSPECIFIED
		}},
		{"account", func(p *apb.ZoneAdmissionLeasePayload) { p.AccountId = "acct-1" }},
		{"pod", func(p *apb.ZoneAdmissionLeasePayload) { p.PodId = "pod-a" }},
		{"assignment generation", func(p *apb.ZoneAdmissionLeasePayload) { p.AssignmentGeneration = 1 }},
		{"session kind", func(p *apb.ZoneAdmissionLeasePayload) { p.SessionKind = mpb.SessionKind_SESSION_KIND_EXEC }},
		{"session leg", func(p *apb.ZoneAdmissionLeasePayload) { p.SessionLeg = mpb.SessionLeg_SESSION_LEG_CLIENT }},
		{"grant", func(p *apb.ZoneAdmissionLeasePayload) { p.GrantId = "grant-1" }},
		{"share", func(p *apb.ZoneAdmissionLeasePayload) { p.ShareId = "share-a" }},
		{"over 24 hours", func(p *apb.ZoneAdmissionLeasePayload) {
			p.NotAfterUnixS = p.NotBeforeUnixS + uint64((apb.MaxNodeLeaseLifetime + time.Second).Seconds())
		}},
	})
}

// TestValidateZoneAdmissionLeasePayloadPodProfile checks the pod leg
// beyond the namespace binding: every identity fact required, the
// assignment generation bound into the pod instance, and no field that
// belongs to another endpoint kind.
func TestValidateZoneAdmissionLeasePayloadPodProfile(t *testing.T) {
	assertPayloadRefusals(t, goldenPodPayload(), []payloadMutation{
		{"missing workload", func(p *apb.ZoneAdmissionLeasePayload) { p.WorkloadId = "" }},
		{"zero generation", func(p *apb.ZoneAdmissionLeasePayload) { p.AssignmentGeneration = 0 }},
		{"node admission", func(p *apb.ZoneAdmissionLeasePayload) {
			p.NodeAdmission = apb.NodeAdmission_NODE_ADMISSION_PROVIDER
		}},
		{"session", func(p *apb.ZoneAdmissionLeasePayload) { p.SessionId = "session-1" }},
		{"grant", func(p *apb.ZoneAdmissionLeasePayload) { p.GrantId = "grant-1" }},
		{"pod-name keyword", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = strings.Replace(p.Principal, "/pod-name/", "/podname/", 1)
		}},
		{"pod identifier mismatch", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = strings.Replace(p.Principal, "/pod/3", "/pod/4", 1)
		}},
	})
}

// TestValidateZoneAdmissionLeasePayloadSessionProfile checks the session
// leg rules not covered by the grant-deadline test: no node admission or
// share, a known session kind and leg, a grant only on the proxy leg, the
// kind and leg spelled in the principal, and at most one hour from
// issuance.
func TestValidateZoneAdmissionLeasePayloadSessionProfile(t *testing.T) {
	assertPayloadRefusals(t, refusalSessionPayload(), []payloadMutation{
		{"missing session", func(p *apb.ZoneAdmissionLeasePayload) { p.SessionId = "" }},
		{"zero generation", func(p *apb.ZoneAdmissionLeasePayload) { p.AssignmentGeneration = 0 }},
		{"node admission", func(p *apb.ZoneAdmissionLeasePayload) {
			p.NodeAdmission = apb.NodeAdmission_NODE_ADMISSION_PROVIDER
		}},
		{"share", func(p *apb.ZoneAdmissionLeasePayload) { p.ShareId = "share-a" }},
		{"unspecified kind", func(p *apb.ZoneAdmissionLeasePayload) {
			p.SessionKind = mpb.SessionKind_SESSION_KIND_UNSPECIFIED
		}},
		{"unknown kind", func(p *apb.ZoneAdmissionLeasePayload) { p.SessionKind = mpb.SessionKind(99) }},
		{"client leg with grant", func(p *apb.ZoneAdmissionLeasePayload) { p.GrantId = "grant-1" }},
		{"proxy leg without grant", func(p *apb.ZoneAdmissionLeasePayload) {
			p.SessionLeg = mpb.SessionLeg_SESSION_LEG_PROXY
			p.Principal = strings.TrimSuffix(p.Principal, "/client") + "/proxy"
		}},
		{"unspecified leg", func(p *apb.ZoneAdmissionLeasePayload) {
			p.SessionLeg = mpb.SessionLeg_SESSION_LEG_UNSPECIFIED
		}},
		{"kind differs from principal", func(p *apb.ZoneAdmissionLeasePayload) {
			p.SessionKind = mpb.SessionKind_SESSION_KIND_LOGS
		}},
		{"leg differs from principal", func(p *apb.ZoneAdmissionLeasePayload) {
			p.SessionLeg = mpb.SessionLeg_SESSION_LEG_PROXY
			p.GrantId = "grant-1"
		}},
		{"over one hour", func(p *apb.ZoneAdmissionLeasePayload) {
			p.NotAfterUnixS = p.IssuedAtUnixS + uint64(apb.MaxSessionLeaseLifetime.Seconds()) + 1
		}},
	})

	for _, kind := range []mpb.SessionKind{mpb.SessionKind_SESSION_KIND_LOGS, mpb.SessionKind_SESSION_KIND_SHELL} {
		p := refusalSessionPayload()
		p.SessionKind = kind
		p.Principal = strings.Replace(p.Principal, "/session/exec/", "/session/"+strings.ToLower(strings.TrimPrefix(kind.String(), "SESSION_KIND_"))+"/", 1)
		if err := wire.ValidateZoneAdmissionLeasePayload(p, p.GetIssuedAtUnixS()); err != nil {
			t.Errorf("%s session refused: %v", kind, err)
		}
	}
}

// TestValidateZoneAdmissionLeaseBindingDeadlines checks the binding
// refusals beyond identity: an absent payload, an SVID deadline of zero, a
// lease outliving its signer, and a session without a grant deadline. Each
// refuses with ErrAdmissionBinding.
func TestValidateZoneAdmissionLeaseBindingDeadlines(t *testing.T) {
	node := refusalNodePayload()
	nodePeer := wire.LeasePeer{
		Principal: node.Principal, SubjectSPKISHA256: node.SubjectSpkiSha256,
		Zone: node.Zone, FabricPlane: node.FabricPlane, EndpointKind: node.EndpointKind,
		SVIDNotAfterUnixS: node.NotAfterUnixS + 3_600, SignerNotAfterUnixS: node.NotAfterUnixS,
	}
	if err := wire.ValidateZoneAdmissionLeaseBinding(node, nodePeer); err != nil {
		t.Fatalf("node lease ending before its SVID and at its signer refused: %v", err)
	}
	session := refusalSessionPayload()
	sessionPeer := wire.LeasePeer{
		Principal: session.Principal, SubjectSPKISHA256: session.SubjectSpkiSha256,
		Zone: session.Zone, FabricPlane: session.FabricPlane, EndpointKind: session.EndpointKind,
		SVIDNotAfterUnixS: session.NotAfterUnixS, GrantNotAfterUnixS: session.NotAfterUnixS,
	}

	rows := []struct {
		name    string
		payload *apb.ZoneAdmissionLeasePayload
		peer    wire.LeasePeer
		mutate  func(*wire.LeasePeer)
	}{
		{"absent payload", nil, nodePeer, func(*wire.LeasePeer) {}},
		{"principal", node, nodePeer, func(p *wire.LeasePeer) { p.Principal += "x" }},
		{"zero SVID deadline", node, nodePeer, func(p *wire.LeasePeer) { p.SVIDNotAfterUnixS = 0 }},
		{"outlives signer", node, nodePeer, func(p *wire.LeasePeer) { p.SignerNotAfterUnixS = node.NotAfterUnixS - 1 }},
		{"session without grant deadline", session, sessionPeer, func(p *wire.LeasePeer) { p.GrantNotAfterUnixS = 0 }},
		{"session ends before SVID", session, sessionPeer, func(p *wire.LeasePeer) { p.SVIDNotAfterUnixS++ }},
	}
	for _, row := range rows {
		peer := row.peer
		row.mutate(&peer)
		if err := wire.ValidateZoneAdmissionLeaseBinding(row.payload, peer); !errors.Is(err, wire.ErrAdmissionBinding) {
			t.Errorf("%s: err = %v, want ErrAdmissionBinding", row.name, err)
		}
	}
}

// TestMarshalZoneAdmissionLeaseRefusals checks that the envelope encoder
// refuses what a parser would refuse: an absent envelope, an absent
// payload, payload bytes that are not canonical, and a payload outside the
// profile. A producer can never emit an envelope a verifier must reject on
// structure.
func TestMarshalZoneAdmissionLeaseRefusals(t *testing.T) {
	if _, err := wire.MarshalZoneAdmissionLeasePayload(nil); !errors.Is(err, wire.ErrAdmissionMalformed) {
		t.Fatalf("nil payload: err = %v, want ErrAdmissionMalformed", err)
	}
	if _, err := wire.MarshalZoneAdmissionLease(nil); !errors.Is(err, wire.ErrAdmissionMalformed) {
		t.Fatalf("nil envelope: err = %v, want ErrAdmissionMalformed", err)
	}
	payloadBytes, err := wire.MarshalZoneAdmissionLeasePayload(goldenPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	expired := goldenPodPayload()
	expired.Version = 2
	expiredBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(expired)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		payload []byte
		want    error
	}{
		{"duplicate trailing field", append(append([]byte(nil), payloadBytes...), 0x08, 0x03), wire.ErrAdmissionNonCanonical},
		{"undecodable", []byte{0x0a, 0x7f}, wire.ErrAdmissionMalformed},
		{"outside the profile", expiredBytes, wire.ErrAdmissionMalformed},
	}
	for _, tc := range cases {
		envelope := hostileLease(t, [][]byte{{0x05}}, bytes.Repeat([]byte{0x04}, apb.SHA256Bytes), placeholderSignature(t))
		envelope.Payload = tc.payload
		if _, err := wire.MarshalZoneAdmissionLease(envelope); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

// TestZoneAdmissionLeaseEnvelopeStructureRefusals checks the envelope
// bounds every parse enforces before any payload or signer judgment: a
// non-canonical signature, a signer key ID that is not a SHA-256 digest,
// and signer chains that are empty, too long, or carry an empty or
// oversized certificate.
func TestZoneAdmissionLeaseEnvelopeStructureRefusals(t *testing.T) {
	keyID := bytes.Repeat([]byte{0x04}, apb.SHA256Bytes)
	bigCert := make([]byte, apb.MaxSignerCertificateDER)
	rows := []struct {
		name   string
		mutate func(*apb.ZoneAdmissionLease)
	}{
		{"empty payload", func(e *apb.ZoneAdmissionLease) { e.Payload = nil }},
		{"oversized payload", func(e *apb.ZoneAdmissionLease) { e.Payload = make([]byte, apb.MaxLeasePayloadBytes+1) }},
		{"high-S signature", func(e *apb.ZoneAdmissionLease) {
			highS := new(big.Int).Sub(p256Order(), big.NewInt(1))
			e.Signature = rawSequence(rawInteger(0x01), rawInteger(paddedIntBytes(highS)...))
		}},
		{"short key id", func(e *apb.ZoneAdmissionLease) { e.SignerKeyId = keyID[:31] }},
		{"empty chain", func(e *apb.ZoneAdmissionLease) { e.SignerCertChain = nil }},
		{"chain too long", func(e *apb.ZoneAdmissionLease) {
			e.SignerCertChain = make([][]byte, apb.MaxSignerChainLength+1)
			for i := range e.SignerCertChain {
				e.SignerCertChain[i] = []byte{0x05}
			}
		}},
		{"empty certificate", func(e *apb.ZoneAdmissionLease) { e.SignerCertChain = [][]byte{{}} }},
		{"oversized certificate", func(e *apb.ZoneAdmissionLease) {
			e.SignerCertChain = [][]byte{make([]byte, apb.MaxSignerCertificateDER+1)}
		}},
		{"chain over the aggregate cap", func(e *apb.ZoneAdmissionLease) {
			e.SignerCertChain = [][]byte{bigCert, bigCert, bigCert, {0x05}}
		}},
	}
	for _, row := range rows {
		envelope := hostileLease(t, [][]byte{{0x05}}, keyID, placeholderSignature(t))
		row.mutate(envelope)
		if _, err := wire.MarshalZoneAdmissionLease(envelope); !errors.Is(err, wire.ErrAdmissionMalformed) {
			t.Errorf("%s: err = %v, want ErrAdmissionMalformed", row.name, err)
		}
		if err := wire.VerifyZoneAdmissionLeaseSignature(envelope, nil); !errors.Is(err, wire.ErrAdmissionMalformed) {
			t.Errorf("%s: signature verification err = %v, want ErrAdmissionMalformed", row.name, err)
		}
	}
	atCap := hostileLease(t, [][]byte{bigCert, bigCert, bigCert}, keyID, placeholderSignature(t))
	if _, err := wire.MarshalZoneAdmissionLease(atCap); err != nil {
		t.Fatalf("chain exactly at the aggregate cap refused: %v", err)
	}
}

// TestVerifyZoneAdmissionLeaseSignature checks raw-payload signature
// verification: the minting key verifies, and every other key, a key on
// another curve, an absent key, a changed payload, and a canonical
// signature over other bytes refuse with ErrAdmissionSignature.
func TestVerifyZoneAdmissionLeaseSignature(t *testing.T) {
	raw, _, signer, _, _ := goldenLease(t)
	envelope, _, err := wire.ParseZoneAdmissionLease(raw, uint64(goldenClock.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	signerKey := signer.Leaf.PublicKey.(*ecdsa.PublicKey)
	if err := wire.VerifyZoneAdmissionLeaseSignature(envelope, signerKey); err != nil {
		t.Fatalf("honest signature refused: %v", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]*ecdsa.PublicKey{
		"other key":  &otherKey.PublicKey,
		"P-384 key":  &p384Key.PublicKey,
		"absent key": nil,
	} {
		if err := wire.VerifyZoneAdmissionLeaseSignature(envelope, key); !errors.Is(err, wire.ErrAdmissionSignature) {
			t.Errorf("%s: err = %v, want ErrAdmissionSignature", name, err)
		}
	}

	tampered := proto.Clone(envelope).(*apb.ZoneAdmissionLease)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if err := wire.VerifyZoneAdmissionLeaseSignature(tampered, signerKey); !errors.Is(err, wire.ErrAdmissionSignature) {
		t.Fatalf("changed payload: err = %v, want ErrAdmissionSignature", err)
	}

	resigned := proto.Clone(envelope).(*apb.ZoneAdmissionLease)
	resigned.Signature, err = wire.SignZoneAdmissionLease(otherKey, envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyZoneAdmissionLeaseSignature(resigned, signerKey); !errors.Is(err, wire.ErrAdmissionSignature) {
		t.Fatalf("signature from another key: err = %v, want ErrAdmissionSignature", err)
	}
}

// TestValidateAdmissionSignerChainDER checks the producer-side chain
// validator: an in-profile chain through an intermediate yields facts that
// match the leaf, and a configured URI that is not a signer identity, a
// leaf for another plane, a non-CA intermediate, and a leaf valid before
// the epoch are each refused.
func TestValidateAdmissionSignerChainDER(t *testing.T) {
	authority := goldenAuthority(t)
	intermediate, err := authority.NewIntermediate()
	if err != nil {
		t.Fatal(err)
	}
	validity := svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_700_050_000, 0))
	signer, err := intermediate.IssueAdmissionSigner(mpb.Plane_PLANE_CONTROL, validity)
	if err != nil {
		t.Fatal(err)
	}
	controlURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := wire.ValidateAdmissionSignerChainDER(signer.ChainDER, controlURI)
	if err != nil {
		t.Fatalf("in-profile chain refused: %v", err)
	}
	if facts.URI != controlURI || !bytes.Equal(facts.KeyID, signer.KeyID) || len(facts.Chain) != 2 ||
		!facts.Leaf.Equal(signer.Leaf) || facts.NotBeforeUnixS != 1_699_999_000 || facts.NotAfterUnixS != 1_700_050_000 {
		t.Fatalf("facts do not describe the leaf: %+v", facts)
	}
	if !facts.PublicKey.Equal(signer.Leaf.PublicKey) {
		t.Fatal("facts public key differs from the leaf key")
	}

	if _, err := wire.ValidateAdmissionSignerChainDER(signer.ChainDER, "spiffe://"+goldenTrustDomain+"/service/other"); err == nil {
		t.Fatal("a configured URI that is not a signer identity was accepted")
	}
	dataURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ValidateAdmissionSignerChainDER(signer.ChainDER, dataURI); !errors.Is(err, wire.ErrAdmissionSignerProfile) {
		t.Fatalf("control signer against the data authority: err = %v, want ErrAdmissionSignerProfile", err)
	}

	peer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_CONTROL, validity)
	if err != nil {
		t.Fatal(err)
	}
	nonCA := [][]byte{signer.ChainDER[0], peer.ChainDER[0]}
	if _, err := wire.ValidateAdmissionSignerChainDER(nonCA, controlURI); !errors.Is(err, wire.ErrAdmissionSignerProfile) {
		t.Fatalf("non-CA intermediate: err = %v, want ErrAdmissionSignerProfile", err)
	}
	if _, err := wire.ValidateAdmissionSignerChainDER([][]byte{{0x30, 0x00}}, controlURI); !errors.Is(err, wire.ErrAdmissionSignerProfile) {
		t.Fatalf("unparseable certificate: err = %v, want ErrAdmissionSignerProfile", err)
	}

	preEpoch, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_CONTROL,
		svidtest.WithValidity(time.Unix(-3_600, 0), time.Unix(3_600, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ValidateAdmissionSignerChainDER(preEpoch.ChainDER, controlURI); !errors.Is(err, wire.ErrAdmissionSignerProfile) {
		t.Fatalf("validity before the epoch: err = %v, want ErrAdmissionSignerProfile", err)
	}
}

// TestValidateExpectedAdmissionSignerURIRefusals checks that a configured
// signer URI must be exactly the canonical signer identity of one plane:
// every other scheme, authority shape, path, or non-canonical spelling is
// refused with the unspecified plane.
func TestValidateExpectedAdmissionSignerURIRefusals(t *testing.T) {
	const data = apb.DataPlaneAdmissionSignerPath
	for _, uri := range []string{
		"",
		"spiffe://" + goldenTrustDomain + "/service/controller/other",
		"spiffe://" + goldenTrustDomain + data + "/",
		"spiffe://" + goldenTrustDomain + data + "?x=1",
		"spiffe://" + goldenTrustDomain + data + "?",
		"spiffe://" + goldenTrustDomain + data + "#f",
		"spiffe://user@" + goldenTrustDomain + data,
		"spiffe://" + goldenTrustDomain + ":8443" + data,
		"spiffe:" + goldenTrustDomain + data,
		"spiffe://" + data,
		"https://" + goldenTrustDomain + data,
		"spiffe://Z1.zone.example.com" + data,
		"spiffe://z1..example.com" + data,
		"spiffe://-z1.example.com" + data,
		"spiffe://" + strings.Repeat("a", 64) + ".example.com" + data,
		"spiffe://" + goldenTrustDomain + "/service/controller%2Fadmission-issuer",
		"spiffe://" + goldenTrustDomain + "/%zz",
	} {
		plane, err := wire.ValidateExpectedAdmissionSignerURI(uri)
		if err == nil {
			t.Errorf("%q accepted as plane %v", uri, plane)
		}
		if plane != mpb.Plane_PLANE_UNSPECIFIED {
			t.Errorf("%q: refusal returned plane %v", uri, plane)
		}
	}
	for _, td := range []string{"", " " + goldenTrustDomain, strings.Repeat("a.", 127) + "a"} {
		if _, err := wire.AdmissionSignerURIForPlane(td, mpb.Plane_PLANE_DATA); err == nil {
			t.Errorf("trust domain %q accepted", td)
		}
	}
}

// TestValidateZoneAdmissionLeaseSignerRefusesNonCanonicalPayload checks
// that the signer judgment re-reads the signed payload canonically before
// comparing lease times with the signer validity: a correctly signed
// envelope whose payload bytes are not the canonical encoding is refused
// with ErrAdmissionNonCanonical, never judged on a decoded approximation.
func TestValidateZoneAdmissionLeaseSignerRefusesNonCanonicalPayload(t *testing.T) {
	_, _, signer, _, _ := goldenLease(t)
	payloadBytes, err := wire.MarshalZoneAdmissionLeasePayload(goldenPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	nonCanonical := append(append([]byte(nil), payloadBytes...), 0x08, 0x03)
	signature, err := wire.SignZoneAdmissionLease(signer.Key, nonCanonical)
	if err != nil {
		t.Fatal(err)
	}
	envelope := hostileLease(t, signer.ChainDER, signer.KeyID, signature)
	envelope.Payload = nonCanonical
	expectedURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(envelope, expectedURI, goldenClock); !errors.Is(err, wire.ErrAdmissionNonCanonical) {
		t.Fatalf("err = %v, want ErrAdmissionNonCanonical", err)
	}
}

// TestAdmissionSignerKeyIDRequiresSPKI checks that the key ID is the
// SHA-256 of the DER SubjectPublicKeyInfo and that a certificate without
// one is refused rather than hashed as empty input.
func TestAdmissionSignerKeyIDRequiresSPKI(t *testing.T) {
	if _, err := wire.AdmissionSignerKeyID(nil); err == nil {
		t.Fatal("nil certificate accepted")
	}
	if _, err := wire.AdmissionSignerKeyID(&x509.Certificate{}); err == nil {
		t.Fatal("certificate without SPKI accepted")
	}
	_, _, signer, _, _ := goldenLease(t)
	got, err := wire.AdmissionSignerKeyID(signer.Leaf)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(signer.Leaf.RawSubjectPublicKeyInfo)
	if !bytes.Equal(got, want[:]) {
		t.Fatal("key ID is not SHA-256 over the SPKI")
	}
}

// TestNormalizeLeaseSignatureLowS checks the producer normalization: a
// high-S signature becomes its low-S twin with the same r, a canonical
// signature is returned unchanged, and malformed produced DER is refused
// with ErrLeaseSignatureEncoding.
func TestNormalizeLeaseSignatureLowS(t *testing.T) {
	r := big.NewInt(5)
	lowS := big.NewInt(7)
	highS := new(big.Int).Sub(p256Order(), lowS)
	high := rawSequence(rawInteger(paddedIntBytes(r)...), rawInteger(paddedIntBytes(highS)...))
	canonical, err := wire.EncodeLeaseSignature(r, lowS)
	if err != nil {
		t.Fatal(err)
	}
	got, err := wire.NormalizeLeaseSignatureLowS(high)
	if err != nil {
		t.Fatalf("high-S normalization: %v", err)
	}
	if !bytes.Equal(got, canonical) {
		t.Fatalf("normalized = %x, want %x", got, canonical)
	}
	if got, err := wire.NormalizeLeaseSignatureLowS(canonical); err != nil || !bytes.Equal(got, canonical) {
		t.Fatalf("canonical input changed to %x, %v", got, err)
	}

	for name, der := range map[string][]byte{
		"empty":           {},
		"wrong outer tag": append([]byte{0x31}, canonical[1:]...),
		"length mismatch": append([]byte{0x30, canonical[1] + 1}, canonical[2:]...),
		"bad r tag":       rawSequence([]byte{0x03, 0x01, 0x01}, rawInteger(0x01)),
		"bad s tag":       rawSequence(rawInteger(0x01), []byte{0x03, 0x01, 0x01}),
		"trailing bytes":  rawSequence(rawInteger(0x01), rawInteger(0x01), []byte{0x05, 0x00}),
		"zero r":          rawSequence(rawInteger(0x00), rawInteger(0x01)),
		"s at the order":  rawSequence(rawInteger(0x01), rawInteger(paddedIntBytes(p256Order())...)),
		"non-minimal s":   rawSequence(rawInteger(0x01), rawInteger(0x00, 0x01)),
		"zero-length s":   rawSequence(rawInteger(0x01), []byte{0x02, 0x00, 0x00}),
	} {
		if _, err := wire.NormalizeLeaseSignatureLowS(der); !errors.Is(err, wire.ErrLeaseSignatureEncoding) {
			t.Errorf("%s: err = %v, want ErrLeaseSignatureEncoding", name, err)
		}
	}
}

// dockProofFixture is one honest dock opening: lease bytes, a predecessor,
// a proof input bound to them, its signature and the endpoint key.
type dockProofFixture struct {
	lease     []byte
	exporter  []byte
	pred      *mpb.DockGen
	input     []byte
	signature []byte
	public    ed25519.PublicKey
	private   ed25519.PrivateKey
}

func newDockProofFixture(t *testing.T) dockProofFixture {
	t.Helper()
	lease, _, _, _, svidKey := goldenLease(t)
	f := dockProofFixture{
		lease:    lease,
		exporter: bytes.Repeat([]byte{0x44}, apb.TLSExporterBytes),
		pred: &mpb.DockGen{
			Edge: &mpb.EdgeTag{Incarnation: []byte("edge-a"), LeaseId: []byte("lease-a")},
			Slot: 7, SlotEpoch: 9, Nonce: []byte("nonce-000001"),
		},
		private: svidKey,
		public:  svidKey.Public().(ed25519.PublicKey),
	}
	input, err := wire.BuildDockProofInput(f.lease, 20_000, f.pred, f.exporter)
	if err != nil {
		t.Fatal(err)
	}
	f.input = input
	f.signature = ed25519.Sign(svidKey, wire.DockProofSignatureInput(input))
	return f
}

// TestBuildDockProofInputRefusals checks that a proof input is built only
// from complete opening facts: a lease within its size bounds, an exporter
// of the exact TLS exporter length, and, when present, an exact
// predecessor generation.
func TestBuildDockProofInputRefusals(t *testing.T) {
	f := newDockProofFixture(t)
	valid := func() *mpb.DockGen { return proto.Clone(f.pred).(*mpb.DockGen) }
	cases := []struct {
		name     string
		lease    []byte
		exporter []byte
		pred     *mpb.DockGen
	}{
		{"empty lease", nil, f.exporter, nil},
		{"oversized lease", make([]byte, apb.MaxLeaseEnvelopeBytes+1), f.exporter, nil},
		{"short exporter", f.lease, f.exporter[:apb.TLSExporterBytes-1], nil},
		{"long exporter", f.lease, append(append([]byte(nil), f.exporter...), 0), nil},
		{"predecessor without edge", f.lease, f.exporter, func() *mpb.DockGen { g := valid(); g.Edge = nil; return g }()},
		{"predecessor without incarnation", f.lease, f.exporter, func() *mpb.DockGen { g := valid(); g.Edge.Incarnation = nil; return g }()},
		{"predecessor incarnation over the cap", f.lease, f.exporter, func() *mpb.DockGen {
			g := valid()
			g.Edge.Incarnation = make([]byte, apb.MaxIdentifierBytes+1)
			return g
		}()},
		{"predecessor without lease id", f.lease, f.exporter, func() *mpb.DockGen { g := valid(); g.Edge.LeaseId = nil; return g }()},
		{"predecessor lease id over the cap", f.lease, f.exporter, func() *mpb.DockGen {
			g := valid()
			g.Edge.LeaseId = make([]byte, apb.MaxIdentifierBytes+1)
			return g
		}()},
		{"predecessor slot zero", f.lease, f.exporter, func() *mpb.DockGen { g := valid(); g.Slot = 0; return g }()},
		{"predecessor short nonce", f.lease, f.exporter, func() *mpb.DockGen { g := valid(); g.Nonce = g.Nonce[:11]; return g }()},
		{"predecessor with unknown field", f.lease, f.exporter, func() *mpb.DockGen {
			g := valid()
			g.ProtoReflect().SetUnknown(unknownVarintField)
			return g
		}()},
	}
	for _, tc := range cases {
		if _, err := wire.BuildDockProofInput(tc.lease, 20_000, tc.pred, tc.exporter); !errors.Is(err, wire.ErrAdmissionMalformed) {
			t.Errorf("%s: err = %v, want ErrAdmissionMalformed", tc.name, err)
		}
	}
}

// TestParseDockProofInputRefusesProfileViolations checks that a canonical
// proof input outside the fixed profile (version, dock contract, exporter
// label, exporter and digest lengths, predecessor shape) or outside its
// size bounds is refused as malformed.
func TestParseDockProofInputRefusesProfileViolations(t *testing.T) {
	f := newDockProofFixture(t)
	parsed, err := wire.ParseDockProofInput(f.input)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(f.lease)
	if !bytes.Equal(parsed.GetLeaseEnvelopeSha256(), digest[:]) || !proto.Equal(parsed.GetPredecessorGen(), f.pred) {
		t.Fatal("parsed proof input does not carry the opening facts")
	}

	for name, mutate := range map[string]func(*apb.DockProofInput){
		"version":         func(p *apb.DockProofInput) { p.Version++ },
		"dock contract":   func(p *apb.DockProofInput) { p.DockContract = "dock/2" },
		"exporter label":  func(p *apb.DockProofInput) { p.ExporterLabel = "EXPORTER-OTHER" },
		"short exporter":  func(p *apb.DockProofInput) { p.ExporterValue = p.ExporterValue[:31] },
		"short digest":    func(p *apb.DockProofInput) { p.LeaseEnvelopeSha256 = p.LeaseEnvelopeSha256[:31] },
		"bad predecessor": func(p *apb.DockProofInput) { p.PredecessorGen.Slot = 0 },
	} {
		m := proto.Clone(parsed).(*apb.DockProofInput)
		mutate(m)
		raw, err := wire.MarshalCanonical(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := wire.ParseDockProofInput(raw); !errors.Is(err, wire.ErrAdmissionMalformed) {
			t.Errorf("%s: err = %v, want ErrAdmissionMalformed", name, err)
		}
	}
	for name, raw := range map[string][]byte{
		"empty":     nil,
		"oversized": make([]byte, apb.MaxDockProofInputBytes+1),
		"truncated": f.input[:len(f.input)-1],
	} {
		if _, err := wire.ParseDockProofInput(raw); !errors.Is(err, wire.ErrAdmissionMalformed) {
			t.Errorf("%s: err = %v, want ErrAdmissionMalformed", name, err)
		}
	}
}

// TestVerifyDockProofRefusalClasses checks that each dock proof refusal
// carries its class: malformed input, a signature or key of the wrong
// length or a signature by another key (ErrAdmissionSignature), and opening
// facts that differ from the signed input (ErrAdmissionBinding).
func TestVerifyDockProofRefusalClasses(t *testing.T) {
	f := newDockProofFixture(t)
	verify := func(input, signature []byte, public ed25519.PublicKey, pred *mpb.DockGen) error {
		return wire.VerifyDockProof(input, signature, public, f.lease, 20_000, pred, f.exporter)
	}
	if err := verify(f.input, f.signature, f.public, f.pred); err != nil {
		t.Fatalf("honest proof refused: %v", err)
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	flipped := append([]byte(nil), f.signature...)
	flipped[0] ^= 1
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"malformed input", verify(f.input[:4], f.signature, f.public, f.pred), wire.ErrAdmissionMalformed},
		{"short signature", verify(f.input, f.signature[:63], f.public, f.pred), wire.ErrAdmissionSignature},
		{"short key", verify(f.input, f.signature, f.public[:31], f.pred), wire.ErrAdmissionSignature},
		{"other key", verify(f.input, f.signature, otherPublic, f.pred), wire.ErrAdmissionSignature},
		{"altered signature", verify(f.input, flipped, f.public, f.pred), wire.ErrAdmissionSignature},
		{"predecessor dropped", verify(f.input, f.signature, f.public, nil), wire.ErrAdmissionBinding},
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, tc.err, tc.want)
		}
	}
	if err := wire.VerifyDockProof(f.input, f.signature, f.public, f.lease, 20_000, f.pred, f.exporter[:31]); !errors.Is(err, wire.ErrAdmissionBinding) {
		t.Fatalf("other exporter: err = %v, want ErrAdmissionBinding", err)
	}
}

// TestValidateDockHelloV3RefusalClasses checks that a dock/3 hello is
// refused as malformed when absent, carrying unknown content, or holding
// fields outside their bounds, and as a binding failure when the signed
// proof input disagrees with the hello's keepalive, predecessor or lease.
func TestValidateDockHelloV3RefusalClasses(t *testing.T) {
	f := newDockProofFixture(t)
	honest := &dockpb.DockHello{
		Contract:           dockpb.Contract,
		KeepaliveMs:        20_000,
		PredecessorGen:     f.pred,
		LeaseEnvelope:      f.lease,
		DockProofInput:     f.input,
		DockProofSignature: f.signature,
	}
	if err := wire.ValidateDockHelloV3(honest); err != nil {
		t.Fatalf("honest hello refused: %v", err)
	}
	if err := wire.ValidateDockHelloV3(nil); !errors.Is(err, wire.ErrAdmissionMalformed) {
		t.Fatalf("nil hello: err = %v, want ErrAdmissionMalformed", err)
	}
	rows := []struct {
		name   string
		mutate func(*dockpb.DockHello)
		want   error
	}{
		{"unknown field", func(h *dockpb.DockHello) { h.ProtoReflect().SetUnknown(unknownVarintField) }, wire.ErrAdmissionMalformed},
		{"unknown nested field", func(h *dockpb.DockHello) {
			h.PredecessorGen.ProtoReflect().SetUnknown(unknownVarintField)
		}, wire.ErrAdmissionMalformed},
		{"oversized lease", func(h *dockpb.DockHello) {
			h.LeaseEnvelope = make([]byte, apb.MaxLeaseEnvelopeBytes+1)
		}, wire.ErrAdmissionMalformed},
		{"oversized proof input", func(h *dockpb.DockHello) {
			h.DockProofInput = make([]byte, apb.MaxDockProofInputBytes+1)
		}, wire.ErrAdmissionMalformed},
		{"short signature", func(h *dockpb.DockHello) { h.DockProofSignature = h.DockProofSignature[:63] }, wire.ErrAdmissionMalformed},
		{"undecodable proof input", func(h *dockpb.DockHello) { h.DockProofInput = []byte{0x0a, 0x7f} }, wire.ErrAdmissionMalformed},
		{"keepalive differs", func(h *dockpb.DockHello) { h.KeepaliveMs++ }, wire.ErrAdmissionBinding},
		{"predecessor differs", func(h *dockpb.DockHello) { h.PredecessorGen.SlotEpoch++ }, wire.ErrAdmissionBinding},
		{"predecessor dropped", func(h *dockpb.DockHello) { h.PredecessorGen = nil }, wire.ErrAdmissionBinding},
		{"lease differs", func(h *dockpb.DockHello) {
			h.LeaseEnvelope = append([]byte(nil), h.LeaseEnvelope...)
			h.LeaseEnvelope[0] ^= 1
		}, wire.ErrAdmissionBinding},
	}
	for _, row := range rows {
		got := proto.Clone(honest).(*dockpb.DockHello)
		row.mutate(got)
		if err := wire.ValidateDockHelloV3(got); !errors.Is(err, row.want) {
			t.Errorf("%s: err = %v, want %v", row.name, err, row.want)
		}
	}
}
