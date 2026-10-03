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
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
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

// Golden canonical encodings. Each constant pins the exact bytes the
// encoder must produce for a fixed input. Changing one is a wire-format
// change: every implementation of the admission contract must produce the
// same bytes for the same input. Verdicts for complete signed leases are
// pinned separately by the conformance corpus under testdata.
const (
	// goldenNodeLeasePayloadHex is the canonical payload encoding of the
	// node lease built in TestZoneAdmissionLeaseClockBoundaries.
	goldenNodeLeasePayloadHex = "08031210010101010101010101010101010101011a027a3120022a387370696666653a2f2f7a312e7a6f6e652e6578616d706c652e636f6d2f7375626e65742f7375626e65742d312f6e6f64652f6e6f64652d3132200202020202020202020202020202020202020202020202020202020202020202380142087375626e65742d314a0b6e6f64653a6e6f64652d316a066e6f64652d31a80101ba010f64796e616d69632d64656661756c74c00101c80180a8d6b907d00180cbdbb907d80101e001bca8d6b907"

	// Parity vectors for the payload, the signed envelope and the dock
	// proof input. They use a placeholder signature, key ID and chain so no
	// randomized cryptography participates, which lets any implementation
	// reproduce them byte for byte.
	goldenParityPodPayloadHex = "08031210303132333435363738396162636465661a027a3120022acf017370696666653a2f2f7a312e7a6f6e652e6578616d706c652e636f6d2f7375626e65742f7375626e65742d312f6163636f756e742f616363742d312f6e616d6573706163652f31313131313131312d313131312d313131312d313131312d3131313131313131313131312f776f726b6c6f61642f32323232323232322d323232322d323232322d323232322d3232323232323232323232322f706f642d6e616d652f64656d6f2f706f642f33333333333333332d333333332d333333332d333333332d3333333333333333333333333220a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5380242087375626e65742d314a2d776f726b6c6f61643a32323232323232322d323232322d323232322d323232322d3232323232323232323232325206616363742d315a2431313131313131312d313131312d313131312d313131312d313131313131313131313131622432323232323232322d323232322d323232322d323232322d3232323232323232323232326a066e6f64652d31722433333333333333332d333333332d333333332d333333332d3333333333333333333333337a2633333333333333332d333333332d333333332d333333332d3333333333333333333333333a37800107a8010cb0010cba010f64796e616d69632d64656661756c74c00101c80180e2cfaa06d001c0b3d2aa06e001bce2cfaa06"
	goldenParityEnvelopeHex   = "0a167a6f6e652d61646d697373696f6e2d6c656173652f3312a60408031210303132333435363738396162636465661a027a3120022acf017370696666653a2f2f7a312e7a6f6e652e6578616d706c652e636f6d2f7375626e65742f7375626e65742d312f6163636f756e742f616363742d312f6e616d6573706163652f31313131313131312d313131312d313131312d313131312d3131313131313131313131312f776f726b6c6f61642f32323232323232322d323232322d323232322d323232322d3232323232323232323232322f706f642d6e616d652f64656d6f2f706f642f33333333333333332d333333332d333333332d333333332d3333333333333333333333333220a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5380242087375626e65742d314a2d776f726b6c6f61643a32323232323232322d323232322d323232322d323232322d3232323232323232323232325206616363742d315a2431313131313131312d313131312d313131312d313131312d313131313131313131313131622432323232323232322d323232322d323232322d323232322d3232323232323232323232326a066e6f64652d31722433333333333333332d333333332d333333332d333333332d3333333333333333333333337a2633333333333333332d333333332d333333332d333333332d3333333333333333333333333a37800107a8010cb0010cba010f64796e616d69632d64656661756c74c00101c80180e2cfaa06d001c0b3d2aa06e001bce2cfaa061a083006020101020101222004040404040404040404040404040404040404040404040404040404040404042a0105"
	goldenParityDockProofHex  = "08011206646f636b2f331a1b4558504f525445522d4944594c2d444f434b2d50524f4f462d7631222044444444444444444444444444444444444444444444444444444444444444442a20abababababababababababababababababababababababababababababababab30a09c013a330a1f0a10656467652d696e6361726e6174696f6e120b726f7574652d6c6561736510071809220c6e6f6e63656e6f6e63653132"
)

const goldenTrustDomain = "z1.zone.example.com"

var goldenClock = time.Unix(1_700_000_060, 0)

func deterministicEd25519(seedStart byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedStart + byte(i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	return privateKey.Public().(ed25519.PublicKey), privateKey
}

func goldenSVIDKey() (ed25519.PublicKey, ed25519.PrivateKey) {
	return deterministicEd25519(0)
}

func goldenAuthority(t *testing.T) *svidtest.Authority {
	t.Helper()
	authority, err := svidtest.NewAuthority(goldenTrustDomain, svidtest.WithClock(func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}))
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func goldenPodPayload() *apb.ZoneAdmissionLeasePayload {
	podID := "33333333-3333-3333-3333-333333333333"
	svidPublicKey, _ := goldenSVIDKey()
	svidSPKI, err := x509.MarshalPKIXPublicKey(svidPublicKey)
	if err != nil {
		panic(err)
	}
	svidKeyID := sha256.Sum256(svidSPKI)
	return &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              []byte("0123456789abcdef"),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_DATA,
		Principal:            "spiffe://z1.zone.example.com/subnet/subnet-1/account/acct-1/namespace/11111111-1111-1111-1111-111111111111/workload/22222222-2222-2222-2222-222222222222/pod-name/demo/pod/" + podID,
		SubjectSpkiSha256:    svidKeyID[:],
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_POD,
		SubnetId:             "subnet-1",
		OwnerScope:           "workload:22222222-2222-2222-2222-222222222222",
		AccountId:            "acct-1",
		NamespaceId:          "11111111-1111-1111-1111-111111111111",
		WorkloadId:           "22222222-2222-2222-2222-222222222222",
		NodeId:               "node-1",
		PodId:                podID,
		PodInstanceId:        podID + ":7",
		AssignmentGeneration: 7,
		AdapterClasses:       wire.LaneClassStream | wire.LaneClassFlow,
		LaneClassCeiling:     wire.LaneClassStream | wire.LaneClassFlow,
		PolicyProfile:        "dynamic-default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       1_700_000_000,
		NotAfterUnixS:        1_700_043_200,
		IssuedAtUnixS:        1_700_000_060,
	}
}

// goldenLease mints one complete, valid zone-admission-lease/3 data-plane
// pod lease under a fresh test authority, and returns it with the
// deterministic endpoint SVID key that signs dock proofs for it.
func goldenLease(t *testing.T) (raw []byte, payload *apb.ZoneAdmissionLeasePayload, signer *svidtest.SignerIdentity, authority *svidtest.Authority, svidKey ed25519.PrivateKey) {
	t.Helper()
	authority = goldenAuthority(t)
	signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA,
		svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_700_050_000, 0)))
	if err != nil {
		t.Fatal(err)
	}
	payload = goldenPodPayload()
	raw, err = signer.SignLease(payload)
	if err != nil {
		t.Fatal(err)
	}
	_, svidKey = goldenSVIDKey()
	return raw, payload, signer, authority, svidKey
}

// parityPodPayload is the fixed input behind the parity vectors: identical
// to goldenPodPayload except for a fixed subject SPKI digest, so no key
// generation participates.
func parityPodPayload() *apb.ZoneAdmissionLeasePayload {
	payload := goldenPodPayload()
	payload.SubjectSpkiSha256 = bytes.Repeat([]byte{0xa5}, apb.SHA256Bytes)
	return payload
}

// TestAdmissionV3CanonicalGoldenVectors checks that the canonical encoder
// reproduces the payload, envelope and dock proof input vectors exactly.
// Signatures and digests are computed over these bytes, so any divergence
// breaks verification between implementations.
func TestAdmissionV3CanonicalGoldenVectors(t *testing.T) {
	payloadBytes, err := wire.MarshalZoneAdmissionLeasePayload(parityPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(payloadBytes); got != goldenParityPodPayloadHex {
		t.Fatalf("pod payload parity golden diverged:\n got %s\nwant %s", got, goldenParityPodPayloadHex)
	}

	placeholder, err := wire.EncodeLeaseSignature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	envelope := &apb.ZoneAdmissionLease{
		Contract:        apb.ZoneAdmissionLeaseContract,
		Payload:         payloadBytes,
		Signature:       placeholder,
		SignerKeyId:     bytes.Repeat([]byte{0x04}, apb.SHA256Bytes),
		SignerCertChain: [][]byte{{0x05}},
	}
	envelopeBytes, err := wire.MarshalCanonical(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(envelopeBytes); got != goldenParityEnvelopeHex {
		t.Fatalf("envelope parity golden diverged:\n got %s\nwant %s", got, goldenParityEnvelopeHex)
	}

	proof := &apb.DockProofInput{
		Version:             apb.DockProofVersion,
		DockContract:        apb.DockContract,
		ExporterLabel:       apb.TLSExporterLabel,
		ExporterValue:       bytes.Repeat([]byte{0x44}, apb.TLSExporterBytes),
		LeaseEnvelopeSha256: bytes.Repeat([]byte{0xab}, apb.SHA256Bytes),
		KeepaliveMs:         20_000,
		PredecessorGen: &mpb.DockGen{
			Edge:      &mpb.EdgeTag{Incarnation: []byte("edge-incarnation"), LeaseId: []byte("route-lease")},
			Slot:      7,
			SlotEpoch: 9,
			Nonce:     []byte("noncenonce12"),
		},
	}
	proofBytes, err := wire.MarshalCanonical(proof)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(proofBytes); got != goldenParityDockProofHex {
		t.Fatalf("dock proof parity golden diverged:\n got %s\nwant %s", got, goldenParityDockProofHex)
	}
}

func TestZoneAdmissionLeaseV2MintParseAndVerify(t *testing.T) {
	raw, payload, signer, authority, _ := goldenLease(t)
	envelope, parsed, err := wire.ParseZoneAdmissionLease(raw, payload.IssuedAtUnixS)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(parsed, payload) {
		t.Fatalf("parsed payload differs:\n got %v\nwant %v", parsed, payload)
	}
	remarshaled, err := wire.MarshalZoneAdmissionLease(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remarshaled, raw) {
		t.Fatal("envelope canonical re-marshal diverged from transmitted bytes")
	}

	expectedURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	facts, err := wire.ValidateZoneAdmissionLeaseSigner(envelope, expectedURI, goldenClock)
	if err != nil {
		t.Fatalf("structural signer validation refused honest lease: %v", err)
	}
	if facts.URI != expectedURI || !bytes.Equal(facts.KeyID, signer.KeyID) {
		t.Fatal("signer facts do not match the minting signer")
	}
	if _, err := wire.VerifyZoneAdmissionLeaseSigner(envelope, authority.Bundle(), expectedURI, nil, goldenClock); err != nil {
		t.Fatalf("trust-anchored verification refused honest lease: %v", err)
	}

	controlURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(envelope, controlURI, goldenClock); err == nil {
		t.Fatal("data-plane signer accepted against the control-plane authority")
	}
}

func TestZoneAdmissionLeaseUnsupportedContractRefusesByName(t *testing.T) {
	// A well-formed envelope whose contract tag names any other contract
	// refuses with ErrAdmissionUnsupportedContract on both the parse path
	// and the signer path, so a caller can tell a contract mismatch from a
	// malformed lease.
	placeholder, err := wire.EncodeLeaseSignature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	v1Shaped := &apb.ZoneAdmissionLease{
		Contract:        "zone-admission-lease/2",
		Payload:         []byte{0x08, 0x01},
		Signature:       placeholder,
		SignerKeyId:     bytes.Repeat([]byte{4}, apb.SHA256Bytes),
		SignerCertChain: [][]byte{{5}},
	}
	raw, err := wire.MarshalCanonical(v1Shaped)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wire.ParseZoneAdmissionLease(raw, uint64(goldenClock.Unix())); !errors.Is(err, wire.ErrAdmissionUnsupportedContract) {
		t.Fatalf("unsupported contract error = %v, want ErrAdmissionUnsupportedContract", err)
	}
	expectedURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(v1Shaped, expectedURI, goldenClock); !errors.Is(err, wire.ErrAdmissionUnsupportedContract) {
		t.Fatalf("signer path error = %v, want ErrAdmissionUnsupportedContract", err)
	}

	// A payload whose version is not apb.PayloadVersion refuses even on the
	// signing side, so it never reaches the wire under this contract.
	_, payload, signer, _, _ := goldenLease(t)
	downgraded := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
	downgraded.Version = 1
	downgradedBytes, err := wire.MarshalCanonical(downgraded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.SignLeasePayloadBytes(downgradedBytes); err == nil {
		t.Fatal("issuer-side marshal of a version-1 payload must refuse")
	}
}

func TestZoneAdmissionLeaseRejectsTamperingAndUnknownContent(t *testing.T) {
	raw, payload, signer, _, _ := goldenLease(t)
	envelope, _, err := wire.ParseZoneAdmissionLease(raw, payload.IssuedAtUnixS)
	if err != nil {
		t.Fatal(err)
	}
	expectedURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		t.Fatal(err)
	}

	tampered := proto.Clone(envelope).(*apb.ZoneAdmissionLease)
	tampered.Payload = append([]byte(nil), tampered.Payload...)
	tampered.Payload[len(tampered.Payload)-1] ^= 1
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(tampered, expectedURI, goldenClock); err == nil {
		t.Fatal("tampered payload must fail its signature")
	}

	unknownPayload := append(append([]byte(nil), envelope.GetPayload()...), 0xf8, 0x07, 0x01) // field 127
	unknownEnvelope := proto.Clone(envelope).(*apb.ZoneAdmissionLease)
	unknownEnvelope.Payload = unknownPayload
	resigned, err := wire.SignZoneAdmissionLease(signer.Key, unknownPayload)
	if err != nil {
		t.Fatal(err)
	}
	unknownEnvelope.Signature = resigned
	unknownRaw, err := wire.MarshalCanonical(unknownEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wire.ParseZoneAdmissionLease(unknownRaw, payload.IssuedAtUnixS); err == nil {
		t.Fatal("unknown critical payload content must fail")
	}

	unknownRaw = append(append([]byte(nil), raw...), 0xf8, 0x07, 0x01)
	if _, _, err := wire.ParseZoneAdmissionLease(unknownRaw, payload.IssuedAtUnixS); err == nil {
		t.Fatal("unknown envelope content must fail")
	}
}

func TestZoneAdmissionLeasePodProfileBindsStableNamespaceID(t *testing.T) {
	honest := goldenPodPayload()
	if err := wire.ValidateZoneAdmissionLeasePayload(honest, honest.GetIssuedAtUnixS()); err != nil {
		t.Fatalf("complete pod lease refused: %v", err)
	}
	rows := []struct {
		name   string
		mutate func(*apb.ZoneAdmissionLeasePayload)
	}{
		{"namespace absent", func(p *apb.ZoneAdmissionLeasePayload) { p.NamespaceId = "" }},
		{"namespace name instead of ID", func(p *apb.ZoneAdmissionLeasePayload) { p.NamespaceId = "default" }},
		{"namespace ID mismatches principal", func(p *apb.ZoneAdmissionLeasePayload) {
			p.NamespaceId = "44444444-4444-4444-4444-444444444444"
		}},
		{"extra qualifying segment", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = strings.Replace(p.Principal, "/namespace/", "/group/g-1/namespace/", 1)
		}},
		{"namespace keyword missing", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = strings.Replace(p.Principal, "/namespace/", "/namespaces/", 1)
		}},
		{"account mismatches principal", func(p *apb.ZoneAdmissionLeasePayload) {
			p.AccountId = "acct-2"
		}},
	}
	for _, row := range rows {
		got := proto.Clone(honest).(*apb.ZoneAdmissionLeasePayload)
		row.mutate(got)
		if err := wire.ValidateZoneAdmissionLeasePayload(got, got.GetIssuedAtUnixS()); !errors.Is(err, wire.ErrAdmissionMalformed) {
			t.Errorf("%s: got %v, want malformed refusal", row.name, err)
		}
	}
}

func TestZoneAdmissionLeaseSessionProfileAndGrantDeadline(t *testing.T) {
	podID := "33333333-3333-3333-3333-333333333333"
	payload := &apb.ZoneAdmissionLeasePayload{
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
		NodeId:               "node-1",
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
	if err := wire.ValidateZoneAdmissionLeasePayload(payload, payload.IssuedAtUnixS); err != nil {
		t.Fatalf("complete client session refused: %v", err)
	}
	peer := wire.LeasePeer{
		Principal: payload.Principal, SubjectSPKISHA256: payload.SubjectSpkiSha256,
		Zone: payload.Zone, FabricPlane: payload.FabricPlane, EndpointKind: payload.EndpointKind,
		SVIDNotAfterUnixS: payload.NotAfterUnixS, GrantNotAfterUnixS: payload.NotAfterUnixS,
	}
	if err := wire.ValidateZoneAdmissionLeaseBinding(payload, peer); err != nil {
		t.Fatalf("grant-bounded client session refused: %v", err)
	}
	peer.GrantNotAfterUnixS++
	if err := wire.ValidateZoneAdmissionLeaseBinding(payload, peer); err == nil {
		t.Fatal("session not_after differing from grant deadline must refuse")
	}

	for name, mutate := range map[string]func(*apb.ZoneAdmissionLeasePayload){
		"account":     func(p *apb.ZoneAdmissionLeasePayload) { p.AccountId = "" },
		"namespace":   func(p *apb.ZoneAdmissionLeasePayload) { p.NamespaceId = "" },
		"workload":    func(p *apb.ZoneAdmissionLeasePayload) { p.WorkloadId = "" },
		"node":        func(p *apb.ZoneAdmissionLeasePayload) { p.NodeId = "" },
		"pod":         func(p *apb.ZoneAdmissionLeasePayload) { p.PodId = "" },
		"incarnation": func(p *apb.ZoneAdmissionLeasePayload) { p.PodInstanceId = "" },
	} {
		got := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
		mutate(got)
		if err := wire.ValidateZoneAdmissionLeasePayload(got, got.GetIssuedAtUnixS()); err == nil {
			t.Errorf("session missing %s must refuse", name)
		}
	}
	proxy := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
	proxy.SessionLeg = mpb.SessionLeg_SESSION_LEG_PROXY
	proxy.GrantId = "grant-1"
	proxy.Principal = strings.TrimSuffix(proxy.Principal, "/client") + "/proxy"
	if err := wire.ValidateZoneAdmissionLeasePayload(proxy, proxy.GetIssuedAtUnixS()); err != nil {
		t.Fatalf("complete proxy session refused: %v", err)
	}

	wrongNamespace := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
	wrongNamespace.NamespaceId = "44444444-4444-4444-4444-444444444444"
	if err := wire.ValidateZoneAdmissionLeasePayload(wrongNamespace, wrongNamespace.GetIssuedAtUnixS()); err == nil {
		t.Fatal("session namespace differing from principal must refuse")
	}

	legacyPodIncarnation := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
	legacyPodIncarnation.PodInstanceId = podID + ":7"
	if err := wire.ValidateZoneAdmissionLeasePayload(legacyPodIncarnation, legacyPodIncarnation.GetIssuedAtUnixS()); err == nil {
		t.Fatal("session lease using pod endpoint incarnation encoding must refuse")
	}
	wrongGeneration := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
	wrongGeneration.PodInstanceId = podID + ".8"
	if err := wire.ValidateZoneAdmissionLeasePayload(wrongGeneration, wrongGeneration.GetIssuedAtUnixS()); err == nil {
		t.Fatal("session lease using the wrong assignment generation must refuse")
	}
}

// shareLeasePayload is one complete share lease: a two-segment data-plane
// principal bound to its share segment and to nothing else (no Subnet,
// account, Node or session).
func shareLeasePayload() *apb.ZoneAdmissionLeasePayload {
	return &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              []byte("share-lease-0001"),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_DATA,
		Principal:            "spiffe://z1.zone.example.com/share/shr_abc123",
		SubjectSpkiSha256:    bytes.Repeat([]byte{0x44}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_SHARE,
		OwnerScope:           "share-owner",
		ShareId:              "shr_abc123",
		AdapterClasses:       wire.LaneClassStream | wire.LaneClassIngressTarget,
		LaneClassCeiling:     wire.LaneClassStream | wire.LaneClassIngressTarget,
		PolicyProfile:        "share-default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       1_700_000_000,
		IssuedAtUnixS:        1_700_000_060,
		NotAfterUnixS:        1_700_003_660,
	}
}

func TestZoneAdmissionLeaseShareProfile(t *testing.T) {
	payload := shareLeasePayload()
	if err := wire.ValidateZoneAdmissionLeasePayload(payload, payload.IssuedAtUnixS); err != nil {
		t.Fatalf("complete share lease refused: %v", err)
	}
	peer := wire.LeasePeer{
		Principal: payload.Principal, SubjectSPKISHA256: payload.SubjectSpkiSha256,
		Zone: payload.Zone, FabricPlane: payload.FabricPlane, EndpointKind: payload.EndpointKind,
		SVIDNotAfterUnixS: payload.NotAfterUnixS,
	}
	if err := wire.ValidateZoneAdmissionLeaseBinding(payload, peer); err != nil {
		t.Fatalf("share bound to its SVID refused: %v", err)
	}
	peer.SVIDNotAfterUnixS++
	if err := wire.ValidateZoneAdmissionLeaseBinding(payload, peer); err == nil {
		t.Fatal("share not_after differing from the SVID must refuse")
	}

	for name, mutate := range map[string]func(*apb.ZoneAdmissionLeasePayload){
		"missing share":       func(p *apb.ZoneAdmissionLeasePayload) { p.ShareId = "" },
		"missing owner scope": func(p *apb.ZoneAdmissionLeasePayload) { p.OwnerScope = "" },
		"share mismatch":      func(p *apb.ZoneAdmissionLeasePayload) { p.ShareId = "shr_other" },
		"control plane":       func(p *apb.ZoneAdmissionLeasePayload) { p.FabricPlane = mpb.Plane_PLANE_CONTROL },
		"extra segment":       func(p *apb.ZoneAdmissionLeasePayload) { p.Principal += "/leg/client" },
		"wrong keyword": func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = "spiffe://z1.zone.example.com/shares/shr_abc123"
		},
		"network form": func(p *apb.ZoneAdmissionLeasePayload) { p.Principal = "spiffe://example.com/share/shr_abc123" },
		"subnet":       func(p *apb.ZoneAdmissionLeasePayload) { p.SubnetId = "subnet-1" },
		"account":      func(p *apb.ZoneAdmissionLeasePayload) { p.AccountId = "acct-1" },
		"node":         func(p *apb.ZoneAdmissionLeasePayload) { p.NodeId = "node-1" },
		"session":      func(p *apb.ZoneAdmissionLeasePayload) { p.SessionId = "session-1" },
		"node admission": func(p *apb.ZoneAdmissionLeasePayload) {
			p.NodeAdmission = apb.NodeAdmission_NODE_ADMISSION_PROVIDER
		},
		"over one hour": func(p *apb.ZoneAdmissionLeasePayload) { p.NotAfterUnixS = p.IssuedAtUnixS + 3_601 },
	} {
		got := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
		mutate(got)
		if err := wire.ValidateZoneAdmissionLeasePayload(got, got.GetIssuedAtUnixS()); err == nil {
			t.Errorf("share lease with %s must refuse", name)
		}
	}

	// Every other kind refuses a share field.
	_, pod, _, _, _ := goldenLease(t)
	pod.ShareId = "shr_abc123"
	if err := wire.ValidateZoneAdmissionLeasePayload(pod, pod.GetIssuedAtUnixS()); err == nil {
		t.Fatal("pod lease carrying share_id must refuse")
	}
}

func TestZoneAdmissionLeaseKindBindingAndLifetimeRefusals(t *testing.T) {
	_, payload, _, _, _ := goldenLease(t)
	peer := wire.LeasePeer{
		Principal:         payload.Principal,
		SubjectSPKISHA256: append([]byte(nil), payload.SubjectSpkiSha256...),
		Zone:              payload.Zone,
		FabricPlane:       payload.FabricPlane,
		EndpointKind:      payload.EndpointKind,
		SVIDNotAfterUnixS: payload.NotAfterUnixS,
	}
	if err := wire.ValidateZoneAdmissionLeaseBinding(payload, peer); err != nil {
		t.Fatalf("honest binding refused: %v", err)
	}

	rows := []struct {
		name string
		mut  func(*wire.LeasePeer)
	}{
		{"copied lease different key", func(p *wire.LeasePeer) { p.SubjectSPKISHA256[0] ^= 1 }},
		{"wrong audience zone", func(p *wire.LeasePeer) { p.Zone = "z2" }},
		{"wrong audience plane", func(p *wire.LeasePeer) { p.FabricPlane = mpb.Plane_PLANE_CONTROL }},
		{"wrong kind", func(p *wire.LeasePeer) { p.EndpointKind = mpb.EndpointKind_ENDPOINT_KIND_NODE }},
		{"lease outlives svid", func(p *wire.LeasePeer) { p.SVIDNotAfterUnixS-- }},
	}
	for _, row := range rows {
		got := peer
		got.SubjectSPKISHA256 = append([]byte(nil), peer.SubjectSPKISHA256...)
		row.mut(&got)
		if err := wire.ValidateZoneAdmissionLeaseBinding(payload, got); err == nil {
			t.Errorf("%s must refuse", row.name)
		}
	}

	wrongPrincipalKind := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
	wrongPrincipalKind.EndpointKind = mpb.EndpointKind_ENDPOINT_KIND_NODE
	if err := wire.ValidateZoneAdmissionLeasePayload(wrongPrincipalKind, wrongPrincipalKind.GetIssuedAtUnixS()); err == nil {
		t.Fatal("principal/kind mismatch must refuse")
	}

	badInstance := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
	badInstance.PodInstanceId = badInstance.GetPodId() + ":8"
	if err := wire.ValidateZoneAdmissionLeasePayload(badInstance, badInstance.GetIssuedAtUnixS()); err == nil {
		t.Fatal("wrong assignment incarnation must refuse")
	}

	badMask := proto.Clone(payload).(*apb.ZoneAdmissionLeasePayload)
	badMask.LaneClassCeiling = 1 << 63
	if err := wire.ValidateZoneAdmissionLeasePayload(badMask, badMask.GetIssuedAtUnixS()); err == nil {
		t.Fatal("unknown capability bit must refuse")
	}
}

func TestZoneAdmissionLeaseClockBoundaries(t *testing.T) {
	_, pod, _, _, _ := goldenLease(t)
	if err := wire.ValidateZoneAdmissionLeasePayload(pod, pod.GetNotBeforeUnixS()); err != nil {
		t.Fatalf("not_before equality must be valid: %v", err)
	}
	if err := wire.ValidateZoneAdmissionLeasePayload(pod, pod.GetNotAfterUnixS()); !errors.Is(err, wire.ErrAdmissionExpired) {
		t.Fatalf("not_after equality error = %v, want ErrAdmissionExpired", err)
	}

	badBackdate := proto.Clone(pod).(*apb.ZoneAdmissionLeasePayload)
	badBackdate.IssuedAtUnixS++
	if err := wire.ValidateZoneAdmissionLeasePayload(badBackdate, badBackdate.GetIssuedAtUnixS()); err == nil {
		t.Fatal("anything but the fixed 60-second backdate must refuse")
	}

	node := &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              bytes.Repeat([]byte{1}, apb.LeaseIDBytes),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_DATA,
		Principal:            "spiffe://z1.zone.example.com/subnet/subnet-1/node/node-1",
		SubjectSpkiSha256:    bytes.Repeat([]byte{2}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_NODE,
		SubnetId:             "subnet-1",
		OwnerScope:           "node:node-1",
		NodeId:               "node-1",
		AdapterClasses:       1,
		PolicyProfile:        "dynamic-default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       2_000_000_000,
		NotAfterUnixS:        2_000_086_400,
		IssuedAtUnixS:        2_000_000_060,
		NodeAdmission:        apb.NodeAdmission_NODE_ADMISSION_PROVIDER,
	}
	if err := wire.ValidateZoneAdmissionLeasePayload(node, node.GetIssuedAtUnixS()); err != nil {
		t.Fatalf("exactly 24h signed interval must be accepted: %v", err)
	}
	nodeRaw, err := wire.MarshalZoneAdmissionLeasePayload(node)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(nodeRaw); got != goldenNodeLeasePayloadHex {
		t.Fatalf("node lease payload golden diverged:\n got %s\nwant %s", got, goldenNodeLeasePayloadHex)
	}
	for name, principal := range map[string]string{
		"non-SPIFFE scheme":  "idyl://example.com/zone/z1/subnet/subnet-1/node/node-1",
		"wrong trust domain": "spiffe://z2.zone.example.com/subnet/subnet-1/node/node-1",
		"pod-shaped path":    "spiffe://z1.zone.example.com/subnet/subnet-1/pod/node-1",
	} {
		wrong := proto.Clone(node).(*apb.ZoneAdmissionLeasePayload)
		wrong.Principal = principal
		if err := wire.ValidateZoneAdmissionLeasePayload(wrong, wrong.GetIssuedAtUnixS()); err == nil {
			t.Errorf("%s node principal must refuse", name)
		}
	}
	node.NotAfterUnixS++
	if err := wire.ValidateZoneAdmissionLeasePayload(node, node.GetIssuedAtUnixS()); err == nil {
		t.Fatal("node signed interval above 24h must refuse")
	}
}

func TestDockProofBindingAndReplayRefusals(t *testing.T) {
	lease, _, _, _, svidKey := goldenLease(t)
	exporter := bytes.Repeat([]byte{0x44}, apb.TLSExporterBytes)
	pred := &mpb.DockGen{
		Edge: &mpb.EdgeTag{Incarnation: []byte("edge-incarnation"), LeaseId: []byte("route-lease")},
		Slot: 7, SlotEpoch: 9, Nonce: []byte("noncenonce12"),
	}
	proofInput, err := wire.BuildDockProofInput(lease, 20_000, pred, exporter)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(svidKey, wire.DockProofSignatureInput(proofInput))
	svidPublic := svidKey.Public().(ed25519.PublicKey)
	if err := wire.VerifyDockProof(proofInput, signature, svidPublic, lease, 20_000, pred, exporter); err != nil {
		t.Fatalf("honest proof refused: %v", err)
	}

	changedExporter := append([]byte(nil), exporter...)
	changedExporter[0] ^= 1
	if err := wire.VerifyDockProof(proofInput, signature, svidPublic, lease, 20_000, pred, changedExporter); err == nil {
		t.Fatal("proof replay on another TLS exporter must refuse")
	}
	if err := wire.VerifyDockProof(proofInput, signature, svidPublic, lease, 20_001, pred, exporter); err == nil {
		t.Fatal("changed opening keepalive must refuse")
	}
	changedPred := proto.Clone(pred).(*mpb.DockGen)
	changedPred.Slot++
	if err := wire.VerifyDockProof(proofInput, signature, svidPublic, lease, 20_000, changedPred, exporter); err == nil {
		t.Fatal("changed opening predecessor must refuse")
	}
	changedLease := append([]byte(nil), lease...)
	changedLease[len(changedLease)-1] ^= 1
	if err := wire.VerifyDockProof(proofInput, signature, svidPublic, changedLease, 20_000, pred, exporter); err == nil {
		t.Fatal("changed opening lease must refuse")
	}
}

func TestDockProofRefusesUnknownAndNonCanonicalRawInput(t *testing.T) {
	lease, _, _, _, svidKey := goldenLease(t)
	exporter := bytes.Repeat([]byte{0x44}, apb.TLSExporterBytes)
	proofInput, err := wire.BuildDockProofInput(lease, 20_000, nil, exporter)
	if err != nil {
		t.Fatal(err)
	}
	svidPublic := svidKey.Public().(ed25519.PublicKey)

	unknown := append(append([]byte(nil), proofInput...), 0xf8, 0x07, 0x01)
	unknownSignature := ed25519.Sign(svidKey, wire.DockProofSignatureInput(unknown))
	if err := wire.VerifyDockProof(unknown, unknownSignature, svidPublic, lease, 20_000, nil, exporter); err == nil {
		t.Fatal("unknown dock proof input field must refuse even with a valid signature")
	}

	// Duplicate version=1 is semantically equal after protobuf decoding but
	// is not the unique canonical encoding, so it must refuse.
	nonCanonical := append(append([]byte(nil), proofInput...), 0x08, 0x01)
	nonCanonicalSignature := ed25519.Sign(svidKey, wire.DockProofSignatureInput(nonCanonical))
	if err := wire.VerifyDockProof(nonCanonical, nonCanonicalSignature, svidPublic, lease, 20_000, nil, exporter); err == nil {
		t.Fatal("non-canonical dock proof input must refuse even with a valid signature")
	}
}

func TestDockHelloRequiresCompleteAdmissionMaterial(t *testing.T) {
	lease, _, _, _, svidKey := goldenLease(t)
	exporter := bytes.Repeat([]byte{0x44}, apb.TLSExporterBytes)
	proofInput, err := wire.BuildDockProofInput(lease, 20_000, nil, exporter)
	if err != nil {
		t.Fatal(err)
	}
	hello := &dockpb.DockHello{
		Contract:           dockpb.Contract,
		KeepaliveMs:        20_000,
		LeaseEnvelope:      lease,
		DockProofInput:     proofInput,
		DockProofSignature: ed25519.Sign(svidKey, wire.DockProofSignatureInput(proofInput)),
	}
	if err := wire.ValidateDockHelloV3(hello); err != nil {
		t.Fatalf("honest hello refused: %v", err)
	}
	for _, mutate := range []func(*dockpb.DockHello){
		func(h *dockpb.DockHello) { h.Contract = "dock/2" },
		func(h *dockpb.DockHello) { h.LeaseEnvelope = nil },
		func(h *dockpb.DockHello) { h.DockProofInput = nil },
		func(h *dockpb.DockHello) { h.DockProofSignature = nil },
	} {
		got := proto.Clone(hello).(*dockpb.DockHello)
		mutate(got)
		if err := wire.ValidateDockHelloV3(got); err == nil {
			t.Fatal("incomplete dock/3 hello must refuse")
		}
	}
}
