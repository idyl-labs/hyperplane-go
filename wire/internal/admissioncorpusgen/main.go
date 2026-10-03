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

// Command admissioncorpusgen generates the zone-admission-lease/3
// conformance corpus, testdata/admissionv3-conformance/corpus.json, which
// is committed to this repository. Run from the wire directory, it writes
// that path by default; -out selects another.
//
// Every vector is evaluated with the Go reference evaluation before it is
// written, and generation fails if any vector's verdict differs from the
// intended one. The fixture keys are generated fresh on each run, are
// test-only, and are discarded when the command exits; they appear in the
// corpus only as public certificates and signatures. Because the keys
// differ on every run, regenerating replaces the bytes of every vector,
// which changes the committed corpus for every consumer.
package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/internal/conformance"
	"github.com/idyl-labs/hyperplane-go/wire/svidtest"
)

const (
	trustDomain = "z1.zone.example.com"
	clockUnixS  = uint64(1_700_000_060)
)

var fixtureClock = func() time.Time { return time.Unix(1_700_000_000, 0) }

func main() {
	out := flag.String("out", "testdata/admissionv3-conformance/corpus.json", "output path")
	flag.Parse()
	corpus, err := build()
	if err != nil {
		log.Fatal(err)
	}
	encoded, err := json.MarshalIndent(corpus, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(*out, encoded, 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %d vectors to %s\n", len(corpus.Vectors), *out)
}

type draft struct {
	name        string
	description string
	envelope    []byte
	expectedURI string
	bundle      []*x509.Certificate
	revoked     [][]byte
	now         uint64
	wantVerdict string
	wantClass   string
}

func build() (*conformance.Corpus, error) {
	authority, err := svidtest.NewAuthority(trustDomain, svidtest.WithClock(fixtureClock))
	if err != nil {
		return nil, err
	}
	foreign, err := svidtest.NewAuthority(trustDomain, svidtest.WithClock(fixtureClock))
	if err != nil {
		return nil, err
	}
	intermediate, err := authority.NewIntermediate()
	if err != nil {
		return nil, err
	}
	validity := svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_700_050_000, 0))
	dataSigner, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, validity)
	if err != nil {
		return nil, err
	}
	controlSigner, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_CONTROL, validity)
	if err != nil {
		return nil, err
	}
	intermediateSigner, err := intermediate.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, validity)
	if err != nil {
		return nil, err
	}
	foreignSigner, err := foreign.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, validity)
	if err != nil {
		return nil, err
	}
	shortSigner, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA,
		svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_700_001_800, 0)))
	if err != nil {
		return nil, err
	}

	dataURI, err := wire.AdmissionSignerURIForPlane(trustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		return nil, err
	}
	controlURI, err := wire.AdmissionSignerURIForPlane(trustDomain, mpb.Plane_PLANE_CONTROL)
	if err != nil {
		return nil, err
	}

	podPayloadBytes, err := wire.MarshalZoneAdmissionLeasePayload(podPayload())
	if err != nil {
		return nil, err
	}
	nodePayloadBytes, err := wire.MarshalZoneAdmissionLeasePayload(nodePayload())
	if err != nil {
		return nil, err
	}
	sharePayloadBytes, err := wire.MarshalZoneAdmissionLeasePayload(sharePayload())
	if err != nil {
		return nil, err
	}
	validPod, err := dataSigner.SignLeasePayloadBytes(podPayloadBytes)
	if err != nil {
		return nil, err
	}
	validNode, err := controlSigner.SignLeasePayloadBytes(nodePayloadBytes)
	if err != nil {
		return nil, err
	}
	validShare, err := dataSigner.SignLeasePayloadBytes(sharePayloadBytes)
	if err != nil {
		return nil, err
	}
	validIntermediate, err := intermediateSigner.SignLeasePayloadBytes(podPayloadBytes)
	if err != nil {
		return nil, err
	}
	foreignLease, err := foreignSigner.SignLeasePayloadBytes(podPayloadBytes)
	if err != nil {
		return nil, err
	}
	outsideLease, err := shortSigner.SignLeasePayloadBytes(podPayloadBytes)
	if err != nil {
		return nil, err
	}

	bundle := authority.Bundle()
	drafts := []draft{
		{
			name:        "valid-pod-data-plane",
			description: "complete pod lease signed by the data-plane admission signer, direct chain",
			envelope:    validPod, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "valid",
		},
		{
			name:        "valid-node-control-plane",
			description: "complete node lease signed by the control-plane admission signer",
			envelope:    validNode, expectedURI: controlURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "valid",
		},
		{
			name:        "valid-share-data-plane",
			description: "complete share lease: two-segment principal, owner scope and share ID only",
			envelope:    validShare, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "valid",
		},
		{
			name:        "share-wrong-plane-signer",
			description: "share lease presented where the control-plane authority is expected",
			envelope:    validShare, expectedURI: controlURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassSignerProfile,
		},
		{
			name:        "valid-with-intermediate",
			description: "signer issued through an intermediate; transmitted chain carries it, bundle holds only the root",
			envelope:    validIntermediate, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "valid",
		},
		{
			name:        "valid-at-not-before-boundary",
			description: "decision clock exactly at payload not_before is valid (zero grace, inclusive start)",
			envelope:    validPod, expectedURI: dataURI, bundle: bundle, now: 1_700_000_000,
			wantVerdict: "valid",
		},
		{
			name:        "expired-at-not-after-boundary",
			description: "decision clock exactly at payload not_after is expired (zero grace, exclusive end)",
			envelope:    validPod, expectedURI: dataURI, bundle: bundle, now: 1_700_043_200,
			wantVerdict: "refused", wantClass: conformance.ClassExpired,
		},
		{
			name:        "not-yet-valid",
			description: "decision clock one second before payload not_before",
			envelope:    validPod, expectedURI: dataURI, bundle: bundle, now: 1_699_999_999,
			wantVerdict: "refused", wantClass: conformance.ClassNotYetValid,
		},
		{
			name:        "unsupported-contract-v1",
			description: "well-formed envelope naming the unsupported zone-admission-lease/1 contract",
			envelope:    v1ContractEnvelope(), expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassUnsupportedContract,
		},
		{
			name:        "non-canonical-envelope",
			description: "valid envelope with a duplicated trailing contract field: decodes equal, not canonical",
			envelope:    appendDuplicateContract(validPod), expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassNonCanonical,
		},
		{
			name:        "truncated-envelope",
			description: "envelope bytes cut mid-field",
			envelope:    validPod[:len(validPod)-3], expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassMalformed,
		},
		{
			name:        "payload-version-1",
			description: "current envelope carrying a payload with version 1",
			envelope:    downgradedVersionEnvelope(dataSigner), expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassMalformed,
		},
		{
			name:        "wrong-plane-signer",
			description: "data-plane signer presented where the control-plane authority is expected",
			envelope:    validPod, expectedURI: controlURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassSignerProfile,
		},
		{
			name:        "untrusted-signer-same-uri",
			description: "foreign authority minted the byte-identical expected URI; trust comes from the bundle, not from the URI text",
			envelope:    foreignLease, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassUntrustedSigner,
		},
		{
			name:        "revoked-signer",
			description: "valid lease whose signer key ID is in the revocation set",
			envelope:    validPod, expectedURI: dataURI, bundle: bundle, revoked: [][]byte{dataSigner.KeyID}, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassRevokedSigner,
		},
		{
			name:        "lease-outside-signer",
			description: "self-consistent payload whose not_after exceeds the signer certificate's not_after",
			envelope:    outsideLease, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassLeaseOutsideSigner,
		},
	}

	hostile, err := hostileSignerDrafts(authority, dataSigner, podPayloadBytes, dataURI, bundle)
	if err != nil {
		return nil, err
	}
	drafts = append(drafts, hostile...)

	signatureDrafts, err := signatureEncodingDrafts(dataSigner, validPod, podPayloadBytes, dataURI, bundle)
	if err != nil {
		return nil, err
	}
	drafts = append(drafts, signatureDrafts...)

	shapeDrafts, err := payloadShapeDrafts(dataSigner, dataURI, bundle)
	if err != nil {
		return nil, err
	}
	drafts = append(drafts, shapeDrafts...)

	shareDrafts, err := shareShapeDrafts(dataSigner, dataURI, bundle)
	if err != nil {
		return nil, err
	}
	drafts = append(drafts, shareDrafts...)

	corpus := &conformance.Corpus{
		Contract:    apb.ZoneAdmissionLeaseContract,
		GeneratedBy: "wire/internal/admissioncorpusgen (generated once; fixture keys are ephemeral test keys)",
		Notes: []string{
			"Every vector's verdict and refusal_class are the Go reference pipeline's output at generation time.",
			"The signer_validity class is unreachable through the reference order (payload time judgments run first and lease times are bounded by signer times); the check remains as defense in depth for other call orders.",
			"Consumers must produce identical verdicts; class mapping for non-Go implementations is documented in README.md.",
		},
	}
	for _, d := range drafts {
		vector := conformance.Vector{
			Name:              d.name,
			Description:       d.description,
			EnvelopeHex:       hex.EncodeToString(d.envelope),
			ExpectedSignerURI: d.expectedURI,
			NowUnixS:          d.now,
			Verdict:           d.wantVerdict,
			RefusalClass:      d.wantClass,
		}
		for _, anchor := range d.bundle {
			vector.TrustBundleDERHex = append(vector.TrustBundleDERHex, hex.EncodeToString(anchor.Raw))
		}
		vector.RevokedSignerKeyIDsHex = []string{}
		for _, keyID := range d.revoked {
			vector.RevokedSignerKeyIDsHex = append(vector.RevokedSignerKeyIDsHex, hex.EncodeToString(keyID))
		}
		verdict, class, err := conformance.Evaluate(vector)
		if err != nil {
			return nil, fmt.Errorf("vector %s: %w", d.name, err)
		}
		if verdict != d.wantVerdict || class != d.wantClass {
			return nil, fmt.Errorf("vector %s: reference verdict %s/%s, intended %s/%s",
				d.name, verdict, class, d.wantVerdict, d.wantClass)
		}
		corpus.Vectors = append(corpus.Vectors, vector)
	}
	return corpus, nil
}

// payloadShapeDrafts covers the pod lease profile: the account and stable
// Namespace ID are required and must match the principal, and principals
// with extra, misnamed, or empty segments are refused. Every envelope is
// correctly signed, so each refusal is a judgment on the payload alone.
func payloadShapeDrafts(signer *svidtest.SignerIdentity, dataURI string, bundle []*x509.Certificate) ([]draft, error) {
	rows := []struct {
		name        string
		description string
		mutate      func(p *apb.ZoneAdmissionLeasePayload)
	}{
		{"pod-namespace-id-absent", "the stable namespace ID is required",
			func(p *apb.ZoneAdmissionLeasePayload) { p.NamespaceId = "" }},
		{"pod-namespace-id-name", "a Namespace name is not a stable Namespace ID",
			func(p *apb.ZoneAdmissionLeasePayload) { p.NamespaceId = "ns-1" }},
		{"pod-namespace-principal-mismatch", "namespace_id disagrees with the principal namespace segment",
			func(p *apb.ZoneAdmissionLeasePayload) { p.NamespaceId = "44444444-4444-4444-4444-444444444444" }},
		{"pod-principal-extra-qualified", "an extra qualifying segment pair is refused by segment count",
			func(p *apb.ZoneAdmissionLeasePayload) {
				p.Principal = strings.Replace(p.Principal, "/namespace/", "/group/g-1/namespace/", 1)
			}},
		{"pod-principal-wrong-prefix", "the Namespace ID rides an unknown segment prefix",
			func(p *apb.ZoneAdmissionLeasePayload) {
				p.Principal = strings.Replace(p.Principal, "/namespace/", "/namespaces/", 1)
			}},
		{"pod-principal-empty-segment",
			"a principal path with an empty segment is refused at parse",
			func(p *apb.ZoneAdmissionLeasePayload) {
				p.Principal = strings.Replace(p.Principal, "/namespace/", "/namespace//", 1)
			}},
	}
	drafts := make([]draft, 0, len(rows))
	for _, row := range rows {
		payload := podPayload()
		row.mutate(payload)
		d, err := malformedDraft(signer, payload, row.name, row.description, dataURI, bundle)
		if err != nil {
			return nil, err
		}
		drafts = append(drafts, d)
	}
	return drafts, nil
}

// shareShapeDrafts covers the share lease profile: the principal is exactly
// /share/{shareID}, share_id matches it, no other kind's field is present,
// the plane is data, and the interval is at most one hour.
func shareShapeDrafts(signer *svidtest.SignerIdentity, dataURI string, bundle []*x509.Certificate) ([]draft, error) {
	rows := []struct {
		name        string
		description string
		mutate      func(p *apb.ZoneAdmissionLeasePayload)
	}{
		{"share-id-principal-mismatch", "share_id disagrees with the principal's share segment",
			func(p *apb.ZoneAdmissionLeasePayload) { p.ShareId = "shr_other" }},
		{"share-id-absent", "the share ID is required",
			func(p *apb.ZoneAdmissionLeasePayload) { p.ShareId = "" }},
		{"share-principal-extra-segment", "a share principal is exactly two segments",
			func(p *apb.ZoneAdmissionLeasePayload) { p.Principal += "/leg/client" }},
		{"share-carries-subnet", "a share is bound to no subnet, node, pod or account",
			func(p *apb.ZoneAdmissionLeasePayload) { p.SubnetId = "subnet-1" }},
		{"share-control-plane", "a share is a data-plane endpoint",
			func(p *apb.ZoneAdmissionLeasePayload) { p.FabricPlane = mpb.Plane_PLANE_CONTROL }},
		{"share-over-one-hour", "a share interval is at most one hour",
			func(p *apb.ZoneAdmissionLeasePayload) { p.NotAfterUnixS = p.IssuedAtUnixS + 3_601 }},
	}
	drafts := make([]draft, 0, len(rows))
	for _, row := range rows {
		payload := sharePayload()
		row.mutate(payload)
		d, err := malformedDraft(signer, payload, row.name, row.description, dataURI, bundle)
		if err != nil {
			return nil, err
		}
		drafts = append(drafts, d)
	}
	return drafts, nil
}

// malformedDraft signs a payload without validating it and expects a
// malformed refusal. The validating signing path refuses to sign such a
// payload; these vectors prove that verification refuses it as well.
func malformedDraft(signer *svidtest.SignerIdentity, payload *apb.ZoneAdmissionLeasePayload, name, description, dataURI string, bundle []*x509.Certificate) (draft, error) {
	payloadBytes, err := wire.MarshalCanonical(payload)
	if err != nil {
		return draft{}, fmt.Errorf("%s: %w", name, err)
	}
	signature, err := wire.SignZoneAdmissionLease(signer.Key, payloadBytes)
	if err != nil {
		return draft{}, fmt.Errorf("%s: %w", name, err)
	}
	envelope, err := wire.MarshalCanonical(&apb.ZoneAdmissionLease{
		Contract:        apb.ZoneAdmissionLeaseContract,
		Payload:         payloadBytes,
		Signature:       signature,
		SignerKeyId:     signer.KeyID,
		SignerCertChain: signer.ChainDER,
	})
	if err != nil {
		return draft{}, fmt.Errorf("%s: %w", name, err)
	}
	return draft{
		name: name, description: description,
		envelope: envelope, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
		wantVerdict: "refused", wantClass: conformance.ClassMalformed,
	}, nil
}

func podPayload() *apb.ZoneAdmissionLeasePayload {
	podID := "33333333-3333-3333-3333-333333333333"
	return &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              []byte("0123456789abcdef"),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_DATA,
		Principal:            "spiffe://z1.zone.example.com/subnet/subnet-1/account/acct-1/namespace/11111111-1111-1111-1111-111111111111/workload/22222222-2222-2222-2222-222222222222/pod-name/demo/pod/" + podID,
		SubjectSpkiSha256:    bytes.Repeat([]byte{0xa5}, apb.SHA256Bytes),
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

func sharePayload() *apb.ZoneAdmissionLeasePayload {
	return &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              bytes.Repeat([]byte{3}, apb.LeaseIDBytes),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_DATA,
		Principal:            "spiffe://z1.zone.example.com/share/shr_abc123",
		SubjectSpkiSha256:    bytes.Repeat([]byte{6}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_SHARE,
		OwnerScope:           "share-owner",
		ShareId:              "shr_abc123",
		AdapterClasses:       wire.LaneClassStream | wire.LaneClassIngressTarget,
		LaneClassCeiling:     wire.LaneClassStream | wire.LaneClassIngressTarget,
		PolicyProfile:        "share-default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       1_700_000_000,
		NotAfterUnixS:        1_700_003_660,
		IssuedAtUnixS:        1_700_000_060,
	}
}

func nodePayload() *apb.ZoneAdmissionLeasePayload {
	return &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              bytes.Repeat([]byte{1}, apb.LeaseIDBytes),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_CONTROL,
		Principal:            "spiffe://z1.zone.example.com/subnet/subnet-1/node/node-1",
		SubjectSpkiSha256:    bytes.Repeat([]byte{2}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_NODE,
		SubnetId:             "subnet-1",
		OwnerScope:           "node:node-1",
		NodeId:               "node-1",
		AdapterClasses:       1,
		PolicyProfile:        "dynamic-default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       1_700_000_000,
		NotAfterUnixS:        1_700_043_200,
		IssuedAtUnixS:        1_700_000_060,
		NodeAdmission:        apb.NodeAdmission_NODE_ADMISSION_PROVIDER,
	}
}

func v1ContractEnvelope() []byte {
	placeholder, err := wire.EncodeLeaseSignature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		panic(err)
	}
	raw, err := wire.MarshalCanonical(&apb.ZoneAdmissionLease{
		Contract:        "zone-admission-lease/1",
		Payload:         []byte{0x08, 0x01},
		Signature:       placeholder,
		SignerKeyId:     bytes.Repeat([]byte{4}, apb.SHA256Bytes),
		SignerCertChain: [][]byte{{5}},
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func appendDuplicateContract(raw []byte) []byte {
	out := append([]byte(nil), raw...)
	out = append(out, 0x0a, byte(len(apb.ZoneAdmissionLeaseContract)))
	return append(out, apb.ZoneAdmissionLeaseContract...)
}

func downgradedVersionEnvelope(signer *svidtest.SignerIdentity) []byte {
	payload := podPayload()
	payload.Version = 1
	payloadBytes, err := wire.MarshalCanonical(payload)
	if err != nil {
		panic(err)
	}
	signature, err := wire.SignZoneAdmissionLease(signer.Key, payloadBytes)
	if err != nil {
		panic(err)
	}
	raw, err := wire.MarshalCanonical(&apb.ZoneAdmissionLease{
		Contract:        apb.ZoneAdmissionLeaseContract,
		Payload:         payloadBytes,
		Signature:       signature,
		SignerKeyId:     signer.KeyID,
		SignerCertChain: signer.ChainDER,
	})
	if err != nil {
		panic(err)
	}
	return raw
}

func hostileSignerDrafts(authority *svidtest.Authority, honest *svidtest.SignerIdentity, payloadBytes []byte, dataURI string, bundle []*x509.Certificate) ([]draft, error) {
	validity := svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_700_050_000, 0))
	ed25519Public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	rows := []struct {
		name        string
		description string
		opts        []svidtest.SignerOption
	}{
		{"ed25519-signer-key", "signer leaf carries an Ed25519 key; only ECDSA P-256 is accepted",
			[]svidtest.SignerOption{validity, svidtest.WithKey(staticPublicSigner{ed25519Public})}},
		{"p384-signer-key", "signer leaf carries a P-384 key",
			[]svidtest.SignerOption{validity, svidtest.WithKey(p384Key)}},
		{"rsa-signer-key", "signer leaf carries an RSA key",
			[]svidtest.SignerOption{validity, svidtest.WithKey(rsaKey)}},
		{"ca-leaf", "signer leaf asserts CA with certSign",
			[]svidtest.SignerOption{validity, svidtest.WithTemplate(func(c *x509.Certificate) {
				c.IsCA = true
				c.KeyUsage |= x509.KeyUsageCertSign
			})}},
		{"certsign-key-usage", "non-CA leaf carrying keyCertSign",
			[]svidtest.SignerOption{validity, svidtest.WithTemplate(func(c *x509.Certificate) {
				c.KeyUsage |= x509.KeyUsageCertSign
			})}},
		{"no-digital-signature", "leaf without the digitalSignature key usage",
			[]svidtest.SignerOption{validity, svidtest.WithTemplate(func(c *x509.Certificate) {
				c.KeyUsage = x509.KeyUsageKeyEncipherment
			})}},
		{"non-svid-eku", "leaf with an extended key usage outside serverAuth/clientAuth",
			[]svidtest.SignerOption{validity, svidtest.WithTemplate(func(c *x509.Certificate) {
				c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
			})}},
		{"dns-san", "leaf carrying a DNS SAN beside the URI SAN",
			[]svidtest.SignerOption{validity, svidtest.WithTemplate(func(c *x509.Certificate) {
				c.DNSNames = []string{"issuer.internal"}
			})}},
		{"over-lifetime-signer", "signer encoded lifetime above the 24h cap",
			[]svidtest.SignerOption{svidtest.WithValidity(time.Unix(1_699_999_000, 0),
				time.Unix(1_699_999_000, 0).Add(apb.MaxAdmissionSignerLifetime+time.Second))}},
		{"foreign-domain-uri", "signer URI names another zone trust domain",
			[]svidtest.SignerOption{validity, svidtest.WithURI("spiffe://z2.zone.example.com/service/admission-signer/data")}},
	}

	placeholder, err := wire.EncodeLeaseSignature(big.NewInt(7), big.NewInt(7))
	if err != nil {
		return nil, err
	}
	drafts := make([]draft, 0, len(rows)+4)
	for _, row := range rows {
		hostile, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, row.opts...)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", row.name, err)
		}
		envelope, err := wire.MarshalCanonical(&apb.ZoneAdmissionLease{
			Contract:        apb.ZoneAdmissionLeaseContract,
			Payload:         payloadBytes,
			Signature:       placeholder,
			SignerKeyId:     hostile.KeyID,
			SignerCertChain: hostile.ChainDER,
		})
		if err != nil {
			return nil, err
		}
		drafts = append(drafts, draft{
			name: row.name, description: row.description,
			envelope: envelope, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassSignerProfile,
		})
	}

	honestSignature, err := wire.SignZoneAdmissionLease(honest.Key, payloadBytes)
	if err != nil {
		return nil, err
	}
	wrongKeyID := append([]byte(nil), honest.KeyID...)
	wrongKeyID[0] ^= 1
	keyIDEnvelope, err := wire.MarshalCanonical(&apb.ZoneAdmissionLease{
		Contract: apb.ZoneAdmissionLeaseContract, Payload: payloadBytes,
		Signature: honestSignature, SignerKeyId: wrongKeyID, SignerCertChain: honest.ChainDER,
	})
	if err != nil {
		return nil, err
	}
	drafts = append(drafts, draft{
		name:        "key-id-mismatch",
		description: "envelope signer_key_id differs from SHA-256 of the leaf SPKI",
		envelope:    keyIDEnvelope, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
		wantVerdict: "refused", wantClass: conformance.ClassSignerProfile,
	})

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	wrongKeySignature, err := wire.SignZoneAdmissionLease(otherKey, payloadBytes)
	if err != nil {
		return nil, err
	}
	wrongKeyEnvelope, err := wire.MarshalCanonical(&apb.ZoneAdmissionLease{
		Contract: apb.ZoneAdmissionLeaseContract, Payload: payloadBytes,
		Signature: wrongKeySignature, SignerKeyId: honest.KeyID, SignerCertChain: honest.ChainDER,
	})
	if err != nil {
		return nil, err
	}
	drafts = append(drafts, draft{
		name:        "wrong-key-signature",
		description: "canonical signature produced by a key other than the presented leaf",
		envelope:    wrongKeyEnvelope, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
		wantVerdict: "refused", wantClass: conformance.ClassSignature,
	})

	longChain, err := wire.MarshalCanonical(&apb.ZoneAdmissionLease{
		Contract: apb.ZoneAdmissionLeaseContract, Payload: payloadBytes,
		Signature: honestSignature, SignerKeyId: honest.KeyID,
		SignerCertChain: [][]byte{honest.ChainDER[0], honest.ChainDER[0], honest.ChainDER[0], honest.ChainDER[0], honest.ChainDER[0]},
	})
	if err != nil {
		return nil, err
	}
	drafts = append(drafts, draft{
		name:        "chain-too-long",
		description: "five chain entries against the bound of four",
		envelope:    longChain, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
		wantVerdict: "refused", wantClass: conformance.ClassMalformed,
	})

	empty, err := proto.MarshalOptions{Deterministic: true}.Marshal(&apb.ZoneAdmissionLease{
		Contract: apb.ZoneAdmissionLeaseContract, Payload: payloadBytes,
		Signature: honestSignature, SignerKeyId: honest.KeyID,
	})
	if err != nil {
		return nil, err
	}
	drafts = append(drafts, draft{
		name:        "empty-signer-chain",
		description: "envelope without any signer certificate",
		envelope:    empty, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
		wantVerdict: "refused", wantClass: conformance.ClassMalformed,
	})
	return drafts, nil
}

func signatureEncodingDrafts(honest *svidtest.SignerIdentity, validPod, payloadBytes []byte, dataURI string, bundle []*x509.Certificate) ([]draft, error) {
	honestSignature, err := wire.SignZoneAdmissionLease(honest.Key, payloadBytes)
	if err != nil {
		return nil, err
	}
	r, s, err := wire.ParseLeaseSignature(honestSignature)
	if err != nil {
		return nil, err
	}
	order := elliptic.P256().Params().N
	highS := new(big.Int).Sub(order, s)
	highSSig := rawSequence(rawInteger(minimalContent(r)), rawInteger(minimalContent(highS)))

	rows := []struct {
		name        string
		description string
		signature   []byte
	}{
		{"high-s-signature", "the valid signature's high-S twin; canonical low-S is required", highSSig},
		{"trailing-der-signature", "valid signature with one trailing byte", append(append([]byte(nil), honestSignature...), 0x00)},
		{"truncated-der-signature", "valid signature missing its final byte", honestSignature[:len(honestSignature)-1]},
		{"non-minimal-der-signature", "integer padded with a redundant leading zero", rawSequence(rawInteger(append([]byte{0x00}, minimalContent(r)...)), rawInteger(minimalContent(s)))},
		{"zero-scalar-signature", "r encoded as zero", rawSequence(rawInteger([]byte{0x00}), rawInteger(minimalContent(s)))},
	}
	drafts := make([]draft, 0, len(rows))
	for _, row := range rows {
		envelope, err := wire.MarshalCanonical(&apb.ZoneAdmissionLease{
			Contract: apb.ZoneAdmissionLeaseContract, Payload: payloadBytes,
			Signature: row.signature, SignerKeyId: honest.KeyID, SignerCertChain: honest.ChainDER,
		})
		if err != nil {
			return nil, err
		}
		drafts = append(drafts, draft{
			name: row.name, description: row.description,
			envelope: envelope, expectedURI: dataURI, bundle: bundle, now: clockUnixS,
			wantVerdict: "refused", wantClass: conformance.ClassMalformed,
		})
	}
	_ = validPod
	return drafts, nil
}

func rawSequence(chunks ...[]byte) []byte {
	body := bytes.Join(chunks, nil)
	out := []byte{0x30, byte(len(body))}
	return append(out, body...)
}

func rawInteger(content []byte) []byte {
	out := []byte{0x02, byte(len(content))}
	return append(out, content...)
}

func minimalContent(value *big.Int) []byte {
	raw := value.Bytes()
	if len(raw) == 0 {
		return []byte{0x00}
	}
	if raw[0]&0x80 != 0 {
		return append([]byte{0x00}, raw...)
	}
	return raw
}

// staticPublicSigner exposes a public key without the ability to sign. It
// is used to mint signer certificates carrying the wrong key type.
type staticPublicSigner struct{ public ed25519.PublicKey }

func (s staticPublicSigner) Public() crypto.PublicKey { return s.public }
func (s staticPublicSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("static public signer cannot sign")
}
