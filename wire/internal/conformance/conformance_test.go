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

package conformance_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/internal/conformance"
	"github.com/idyl-labs/hyperplane-go/wire/svidtest"
)

const (
	corpusPath       = "../../testdata/admissionv3-conformance/corpus.json"
	corpusDigestPath = "../../testdata/admissionv3-conformance/corpus.sha256"
	trustDomain      = "zone-a.zone.example.com"
	// leaseNotBefore and leaseNotAfter bound every hand-built lease; the
	// lease is issued at leaseNotBefore plus the fixed issuer backdate.
	leaseNotBefore = uint64(1_700_000_000)
	leaseNotAfter  = leaseNotBefore + 6*3600
)

// allClasses is the refusal-class vocabulary.
var allClasses = []string{
	conformance.ClassUnsupportedContract, conformance.ClassMalformed, conformance.ClassNonCanonical,
	conformance.ClassNotYetValid, conformance.ClassExpired, conformance.ClassSignerProfile,
	conformance.ClassSignerValidity, conformance.ClassUntrustedSigner, conformance.ClassRevokedSigner,
	conformance.ClassLeaseOutsideSigner, conformance.ClassSignature,
}

// TestClassVocabulary pins the refusal-class strings. Implementations in
// other languages compare these exact values against the corpus.
func TestClassVocabulary(t *testing.T) {
	want := "unsupported_contract malformed non_canonical not_yet_valid expired signer_profile " +
		"signer_validity untrusted_signer revoked_signer lease_outside_signer signature"
	if got := strings.Join(allClasses, " "); got != want {
		t.Fatalf("classes = %q, want %q", got, want)
	}
}

// TestCommittedCorpusLoads checks the committed corpus file: its bytes
// match the committed digest, it decodes strictly into the published
// schema, it names this contract, every vector is well formed under the
// schema's rules, and every vector's recorded verdict is what Evaluate
// derives today.
func TestCommittedCorpusLoads(t *testing.T) {
	raw, err := os.ReadFile(corpusPath)
	if err != nil {
		t.Fatal(err)
	}
	digestFile, err := os.ReadFile(corpusDigestPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if got := strings.TrimSpace(string(digestFile)); got != hex.EncodeToString(digest[:]) {
		t.Fatalf("corpus digest file %q does not match the corpus", got)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var corpus conformance.Corpus
	if err := decoder.Decode(&corpus); err != nil {
		t.Fatalf("corpus does not match the schema: %v", err)
	}
	if corpus.Contract != apb.ZoneAdmissionLeaseContract || corpus.GeneratedBy == "" {
		t.Fatalf("corpus header: contract %q, generated_by %q", corpus.Contract, corpus.GeneratedBy)
	}
	known := map[string]bool{}
	for _, class := range allClasses {
		known[class] = true
	}
	names := map[string]bool{}
	for _, vector := range corpus.Vectors {
		if vector.Name == "" || names[vector.Name] || vector.Description == "" {
			t.Errorf("vector %q: name missing or duplicated, or description missing", vector.Name)
		}
		names[vector.Name] = true
		switch vector.Verdict {
		case "valid":
			if vector.RefusalClass != "" {
				t.Errorf("vector %s: valid vector names refusal class %q", vector.Name, vector.RefusalClass)
			}
		case "refused":
			if !known[vector.RefusalClass] {
				t.Errorf("vector %s: refusal class %q is outside the vocabulary", vector.Name, vector.RefusalClass)
			}
		default:
			t.Errorf("vector %s: verdict %q", vector.Name, vector.Verdict)
		}
		if vector.RevokedSignerKeyIDsHex == nil || len(vector.TrustBundleDERHex) == 0 {
			t.Errorf("vector %s: bundle or revocation list absent", vector.Name)
		}
		verdict, class, err := conformance.Evaluate(vector)
		if err != nil {
			t.Errorf("vector %s: %v", vector.Name, err)
			continue
		}
		if verdict != vector.Verdict || class != vector.RefusalClass {
			t.Errorf("vector %s: evaluated %s/%s, recorded %s/%s", vector.Name, verdict, class, vector.Verdict, vector.RefusalClass)
		}
	}
}

// vectorKit holds the fixture PKI hand-built vectors are made from.
type vectorKit struct {
	authority  *svidtest.Authority
	foreign    *svidtest.Authority
	signer     *svidtest.SignerIdentity
	short      *svidtest.SignerIdentity
	controlURI string
	dataURI    string
	payload    []byte
}

func newVectorKit(t *testing.T) vectorKit {
	t.Helper()
	clock := svidtest.WithClock(func() time.Time { return time.Unix(int64(leaseNotBefore), 0) })
	authority, err := svidtest.NewAuthority(trustDomain, clock)
	if err != nil {
		t.Fatal(err)
	}
	foreign, err := svidtest.NewAuthority(trustDomain, clock)
	if err != nil {
		t.Fatal(err)
	}
	signerFrom := time.Unix(int64(leaseNotBefore)-600, 0)
	signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_CONTROL, svidtest.WithValidity(signerFrom, signerFrom.Add(12*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	short, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_CONTROL, svidtest.WithValidity(signerFrom, signerFrom.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	controlURI, err := wire.AdmissionSignerURIForPlane(trustDomain, mpb.Plane_PLANE_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	dataURI, err := wire.AdmissionSignerURIForPlane(trustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := wire.MarshalZoneAdmissionLeasePayload(&apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              bytes.Repeat([]byte{1}, apb.LeaseIDBytes),
		Zone:                 "zone-a",
		FabricPlane:          mpb.Plane_PLANE_CONTROL,
		Principal:            "spiffe://" + trustDomain + "/subnet/subnet-a/node/node-a",
		SubjectSpkiSha256:    bytes.Repeat([]byte{2}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_NODE,
		SubnetId:             "subnet-a",
		OwnerScope:           "node:node-a",
		NodeId:               "node-a",
		AdapterClasses:       1,
		PolicyProfile:        "default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       leaseNotBefore,
		IssuedAtUnixS:        leaseNotBefore + 60,
		NotAfterUnixS:        leaseNotAfter,
		NodeAdmission:        apb.NodeAdmission_NODE_ADMISSION_PROVIDER,
	})
	if err != nil {
		t.Fatal(err)
	}
	return vectorKit{authority: authority, foreign: foreign, signer: signer, short: short, controlURI: controlURI, dataURI: dataURI, payload: payload}
}

// envelope signs the kit's payload with signer and returns the canonical
// envelope.
func (k vectorKit) envelope(t *testing.T, signer *svidtest.SignerIdentity) []byte {
	t.Helper()
	raw, err := signer.SignLeasePayloadBytes(k.payload)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// vector builds a vector over envelope trusted by the kit's authority,
// expecting the control-plane signer, evaluated at now.
func (k vectorKit) vector(envelope []byte, now uint64) conformance.Vector {
	return conformance.Vector{
		Name:                   "hand-built",
		EnvelopeHex:            hex.EncodeToString(envelope),
		ExpectedSignerURI:      k.controlURI,
		TrustBundleDERHex:      []string{hex.EncodeToString(k.authority.Bundle()[0].Raw)},
		RevokedSignerKeyIDsHex: []string{},
		NowUnixS:               now,
	}
}

// TestEvaluateHandBuiltVectors checks that Evaluate reaches a valid
// verdict for an honest lease and every refusal class the reference order
// can produce, each from a vector that differs from the valid one in one
// fact. The boundary vectors pin the zero-grace window: valid at
// not_before, expired at not_after.
func TestEvaluateHandBuiltVectors(t *testing.T) {
	k := newVectorKit(t)
	honest := k.envelope(t, k.signer)
	now := leaseNotBefore + 60

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forgedSignature, err := wire.SignZoneAdmissionLease(otherKey, k.payload)
	if err != nil {
		t.Fatal(err)
	}
	forged := canonicalEnvelope(t, apb.ZoneAdmissionLeaseContract, k.payload, forgedSignature, k.signer)
	placeholder, err := wire.EncodeLeaseSignature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		t.Fatal(err)
	}
	oldContract := canonicalEnvelope(t, "zone-admission-lease/1", k.payload, placeholder, k.signer)
	duplicated := append(append([]byte(nil), honest...), 0x0a, byte(len(apb.ZoneAdmissionLeaseContract)))
	duplicated = append(duplicated, apb.ZoneAdmissionLeaseContract...)

	for _, row := range []struct {
		name    string
		vector  conformance.Vector
		verdict string
		class   string
	}{
		{"valid", k.vector(honest, now), "valid", ""},
		{"valid at not_before", k.vector(honest, leaseNotBefore), "valid", ""},
		{"unsupported contract", k.vector(oldContract, now), "refused", conformance.ClassUnsupportedContract},
		{"truncated envelope", k.vector(honest[:len(honest)-3], now), "refused", conformance.ClassMalformed},
		{"empty envelope", k.vector(nil, now), "refused", conformance.ClassMalformed},
		{"non-canonical envelope", k.vector(duplicated, now), "refused", conformance.ClassNonCanonical},
		{"not yet valid", k.vector(honest, leaseNotBefore-1), "refused", conformance.ClassNotYetValid},
		{"expired at not_after", k.vector(honest, leaseNotAfter), "refused", conformance.ClassExpired},
		{"wrong plane signer", func() conformance.Vector {
			v := k.vector(honest, now)
			v.ExpectedSignerURI = k.dataURI
			return v
		}(), "refused", conformance.ClassSignerProfile},
		{"untrusted signer", func() conformance.Vector {
			v := k.vector(honest, now)
			v.TrustBundleDERHex = []string{hex.EncodeToString(k.foreign.Bundle()[0].Raw)}
			return v
		}(), "refused", conformance.ClassUntrustedSigner},
		{"empty bundle", func() conformance.Vector {
			v := k.vector(honest, now)
			v.TrustBundleDERHex = nil
			return v
		}(), "refused", conformance.ClassUntrustedSigner},
		{"revoked signer", func() conformance.Vector {
			v := k.vector(honest, now)
			v.RevokedSignerKeyIDsHex = []string{hex.EncodeToString(k.signer.KeyID)}
			return v
		}(), "refused", conformance.ClassRevokedSigner},
		{"lease outside signer", k.vector(k.envelope(t, k.short), now), "refused", conformance.ClassLeaseOutsideSigner},
		{"forged signature", k.vector(forged, now), "refused", conformance.ClassSignature},
	} {
		t.Run(row.name, func(t *testing.T) {
			verdict, class, err := conformance.Evaluate(row.vector)
			if err != nil {
				t.Fatalf("vector did not decode: %v", err)
			}
			if verdict != row.verdict || class != row.class {
				t.Fatalf("got %s/%s, want %s/%s", verdict, class, row.verdict, row.class)
			}
		})
	}
}

// TestEvaluateRefusesUndecodableVectors checks that a vector whose own
// hex or certificates cannot be decoded is an error, never a verdict: a
// broken vector must not be mistaken for a refusal.
func TestEvaluateRefusesUndecodableVectors(t *testing.T) {
	k := newVectorKit(t)
	base := k.vector(k.envelope(t, k.signer), leaseNotBefore+60)
	for name, mutate := range map[string]func(*conformance.Vector){
		"envelope hex":    func(v *conformance.Vector) { v.EnvelopeHex = "zz" },
		"odd hex":         func(v *conformance.Vector) { v.EnvelopeHex = "abc" },
		"bundle hex":      func(v *conformance.Vector) { v.TrustBundleDERHex = []string{"zz"} },
		"bundle DER":      func(v *conformance.Vector) { v.TrustBundleDERHex = []string{"3000"} },
		"revoked key hex": func(v *conformance.Vector) { v.RevokedSignerKeyIDsHex = []string{"not-hex"} },
	} {
		vector := base
		mutate(&vector)
		verdict, class, err := conformance.Evaluate(vector)
		if err == nil || verdict != "" || class != "" {
			t.Errorf("%s: got %q/%q, err %v; want an error and no verdict", name, verdict, class, err)
		}
		if err != nil && !strings.Contains(err.Error(), base.Name) {
			t.Errorf("%s: error %q does not name the vector", name, err)
		}
	}
}

// TestClassifyMapsEveryTypedCause checks that each typed refusal maps to
// its class, including through wrapping, that signer_validity is reachable
// by Classify even though the reference order never produces it, and
// that an untyped error is malformed.
func TestClassifyMapsEveryTypedCause(t *testing.T) {
	for _, row := range []struct {
		err   error
		class string
	}{
		{wire.ErrAdmissionUnsupportedContract, conformance.ClassUnsupportedContract},
		{wire.ErrAdmissionNonCanonical, conformance.ClassNonCanonical},
		{wire.ErrAdmissionNotYetValid, conformance.ClassNotYetValid},
		{wire.ErrAdmissionExpired, conformance.ClassExpired},
		{wire.ErrAdmissionLeaseOutsideSigner, conformance.ClassLeaseOutsideSigner},
		{wire.ErrAdmissionSignerRevoked, conformance.ClassRevokedSigner},
		{wire.ErrAdmissionSignerUntrusted, conformance.ClassUntrustedSigner},
		{wire.ErrAdmissionSignerValidity, conformance.ClassSignerValidity},
		{wire.ErrAdmissionSignerProfile, conformance.ClassSignerProfile},
		{wire.ErrAdmissionSignature, conformance.ClassSignature},
		{wire.ErrLeaseSignatureEncoding, conformance.ClassSignature},
		{wire.ErrAdmissionMalformed, conformance.ClassMalformed},
		{errors.New("untyped"), conformance.ClassMalformed},
		{nil, conformance.ClassMalformed},
	} {
		if got := conformance.Classify(row.err); got != row.class {
			t.Errorf("Classify(%v) = %q, want %q", row.err, got, row.class)
		}
		if row.err != nil {
			if got := conformance.Classify(fmt.Errorf("context: %w", row.err)); got != row.class {
				t.Errorf("Classify(wrapped %v) = %q, want %q", row.err, got, row.class)
			}
		}
	}
}

// TestClassifyPrefersTheMostSpecificClass checks the documented order:
// when an error carries several typed causes, the earlier, more specific
// class wins, so every implementation reports the same class.
func TestClassifyPrefersTheMostSpecificClass(t *testing.T) {
	for _, row := range []struct {
		causes []error
		class  string
	}{
		{[]error{wire.ErrAdmissionSignerProfile, wire.ErrAdmissionUnsupportedContract}, conformance.ClassUnsupportedContract},
		{[]error{wire.ErrAdmissionMalformed, wire.ErrAdmissionNonCanonical}, conformance.ClassNonCanonical},
		{[]error{wire.ErrAdmissionSignerUntrusted, wire.ErrAdmissionSignerRevoked}, conformance.ClassRevokedSigner},
		{[]error{wire.ErrAdmissionSignature, wire.ErrAdmissionSignerProfile}, conformance.ClassSignerProfile},
		{[]error{wire.ErrAdmissionSignerValidity, wire.ErrAdmissionExpired}, conformance.ClassExpired},
	} {
		if got := conformance.Classify(errors.Join(row.causes...)); got != row.class {
			t.Errorf("Classify(%v) = %q, want %q", row.causes, got, row.class)
		}
	}
}

// canonicalEnvelope encodes an envelope with the given contract, payload
// and signature, carrying signer's key ID and chain, without the
// validation MarshalZoneAdmissionLease applies.
func canonicalEnvelope(t *testing.T, contract string, payload, signature []byte, signer *svidtest.SignerIdentity) []byte {
	t.Helper()
	raw, err := wire.MarshalCanonical(&apb.ZoneAdmissionLease{
		Contract:        contract,
		Payload:         payload,
		Signature:       signature,
		SignerKeyId:     signer.KeyID,
		SignerCertChain: signer.ChainDER,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
