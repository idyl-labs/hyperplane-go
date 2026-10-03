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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/svidtest"
)

func TestAdmissionSignerURIDerivation(t *testing.T) {
	control, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_CONTROL)
	if err != nil || control != "spiffe://"+goldenTrustDomain+"/service/admission-signer/control" {
		t.Fatalf("control authority = %q err=%v", control, err)
	}
	data, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_DATA)
	if err != nil || data != "spiffe://"+goldenTrustDomain+"/service/admission-signer/data" {
		t.Fatalf("data authority = %q err=%v", data, err)
	}
	if _, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_UNSPECIFIED); err == nil {
		t.Fatal("unspecified plane must have no signer authority")
	}
	if _, err := wire.AdmissionSignerURIForPlane("Not A Domain", mpb.Plane_PLANE_DATA); err == nil {
		t.Fatal("invalid trust domain must refuse")
	}

	for name, uri := range map[string]string{
		"wrong path":       "spiffe://" + goldenTrustDomain + "/service/admission-signer",
		"query":            data + "?x=1",
		"fragment":         data + "#f",
		"port":             "spiffe://" + goldenTrustDomain + ":443/service/admission-signer/data",
		"userinfo":         "spiffe://user@" + goldenTrustDomain + "/service/admission-signer/data",
		"uppercase domain": "spiffe://Z1.zone.example.com/service/admission-signer/data",
		"http scheme":      "https://" + goldenTrustDomain + "/service/admission-signer/data",
		"empty":            "",
	} {
		if _, err := wire.ValidateExpectedAdmissionSignerURI(uri); err == nil {
			t.Errorf("%s expected-signer URI must refuse", name)
		}
	}
	plane, err := wire.ValidateExpectedAdmissionSignerURI(control)
	if err != nil || plane != mpb.Plane_PLANE_CONTROL {
		t.Fatalf("control URI plane = %v err=%v", plane, err)
	}
}

// hostileLease signs the golden pod payload with an arbitrary signer chain
// and key facts, bypassing producer-side validation.
func hostileLease(t *testing.T, chainDER [][]byte, keyID []byte, signature []byte) *apb.ZoneAdmissionLease {
	t.Helper()
	payloadBytes, err := wire.MarshalZoneAdmissionLeasePayload(goldenPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	return &apb.ZoneAdmissionLease{
		Contract:        apb.ZoneAdmissionLeaseContract,
		Payload:         payloadBytes,
		Signature:       signature,
		SignerKeyId:     keyID,
		SignerCertChain: chainDER,
	}
}

func placeholderSignature(t *testing.T) []byte {
	t.Helper()
	signature, err := wire.EncodeLeaseSignature(big.NewInt(7), big.NewInt(7))
	if err != nil {
		t.Fatal(err)
	}
	return signature
}

// TestAdmissionSignerProfileRefusals mints signer certificates that each
// break one rule of the admission signer profile (URI SAN, CA status, key
// usage, extended key usage, key algorithm, lifetime) and requires the
// structural validator to refuse every one, along with malformed, oversized
// and mismatched signer chains.
func TestAdmissionSignerProfileRefusals(t *testing.T) {
	authority := goldenAuthority(t)
	expectedURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	validity := svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_700_050_000, 0))

	ed25519Public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	otherPlaneURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	extraURI, err := url.Parse("spiffe://" + goldenTrustDomain + "/service/other")
	if err != nil {
		t.Fatal(err)
	}

	rows := map[string][]svidtest.SignerOption{
		"wrong plane URI":    {validity, svidtest.WithURI(otherPlaneURI)},
		"foreign domain URI": {validity, svidtest.WithURI("spiffe://z2.zone.example.com/service/admission-signer/data")},
		"CA leaf": {validity, svidtest.WithTemplate(func(c *x509.Certificate) {
			c.IsCA = true
			c.KeyUsage |= x509.KeyUsageCertSign
		})},
		"certSign key usage": {validity, svidtest.WithTemplate(func(c *x509.Certificate) {
			c.KeyUsage |= x509.KeyUsageCertSign
		})},
		"crlSign key usage": {validity, svidtest.WithTemplate(func(c *x509.Certificate) {
			c.KeyUsage |= x509.KeyUsageCRLSign
		})},
		"no digital signature": {validity, svidtest.WithTemplate(func(c *x509.Certificate) {
			c.KeyUsage = x509.KeyUsageKeyEncipherment
		})},
		"non-SVID EKU": {validity, svidtest.WithTemplate(func(c *x509.Certificate) {
			c.ExtKeyUsage = append(c.ExtKeyUsage, x509.ExtKeyUsageEmailProtection)
		})},
		"unknown EKU": {validity, svidtest.WithTemplate(func(c *x509.Certificate) {
			c.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{1, 3, 6, 1, 4, 1, 99999, 31, 1}}
		})},
		"second URI SAN": {validity, svidtest.WithTemplate(func(c *x509.Certificate) {
			c.URIs = []*url.URL{mustParseURI(t, expectedURI), extraURI}
		})},
		"DNS SAN": {validity, svidtest.WithTemplate(func(c *x509.Certificate) {
			c.DNSNames = []string{"issuer.internal"}
		})},
		"Ed25519 key":     {validity, svidtest.WithKey(fixedSigner{ed25519Public})},
		"P-384 key":       {validity, svidtest.WithKey(p384Key)},
		"RSA key":         {validity, svidtest.WithKey(rsaKey)},
		"over-cap signer": {svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_699_999_000, 0).Add(apb.MaxAdmissionSignerLifetime+time.Second))},
	}
	for name, opts := range rows {
		signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, opts...)
		if err != nil {
			t.Fatalf("%s: mint hostile signer: %v", name, err)
		}
		envelope := hostileLease(t, signer.ChainDER, signer.KeyID, placeholderSignature(t))
		if _, err := wire.ValidateZoneAdmissionLeaseSigner(envelope, expectedURI, goldenClock); err == nil {
			t.Errorf("%s must refuse", name)
		}
	}

	honest, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, validity)
	if err != nil {
		t.Fatal(err)
	}
	honestRaw, err := honest.SignLease(goldenPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	honestEnvelope, _, err := wire.ParseZoneAdmissionLease(honestRaw, uint64(goldenClock.Unix()))
	if err != nil {
		t.Fatal(err)
	}

	wrongKeyID := hostileLease(t, honest.ChainDER, flipFirstByte(honest.KeyID), honestEnvelope.GetSignature())
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(wrongKeyID, expectedURI, goldenClock); err == nil {
		t.Fatal("signer key-id mismatch must refuse")
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongKeySignature, err := wire.SignZoneAdmissionLease(otherKey, honestEnvelope.GetPayload())
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := hostileLease(t, honest.ChainDER, honest.KeyID, wrongKeySignature)
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(wrongKey, expectedURI, goldenClock); !errors.Is(err, wire.ErrAdmissionSignature) {
		t.Fatalf("wrong-key signature error = %v, want ErrAdmissionSignature", err)
	}

	longChain := hostileLease(t, [][]byte{honest.ChainDER[0], honest.ChainDER[0], honest.ChainDER[0], honest.ChainDER[0], honest.ChainDER[0]}, honest.KeyID, honestEnvelope.GetSignature())
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(longChain, expectedURI, goldenClock); err == nil {
		t.Fatal("over-length signer chain must refuse")
	}

	oversized := bytes.Repeat([]byte{0x30}, 3584)
	aggregate := hostileLease(t, [][]byte{oversized, oversized, oversized, oversized}, honest.KeyID, honestEnvelope.GetSignature())
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(aggregate, expectedURI, goldenClock); err == nil {
		t.Fatal("aggregate chain size above the bound must refuse")
	}

	duplicateLeaf := hostileLease(t, [][]byte{honest.ChainDER[0], honest.ChainDER[0]}, honest.KeyID, honestEnvelope.GetSignature())
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(duplicateLeaf, expectedURI, goldenClock); err == nil {
		t.Fatal("non-CA second chain certificate must refuse")
	}

	empty := hostileLease(t, nil, honest.KeyID, honestEnvelope.GetSignature())
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(empty, expectedURI, goldenClock); err == nil {
		t.Fatal("empty signer chain must refuse")
	}

	garbage := hostileLease(t, [][]byte{append(append([]byte(nil), honest.ChainDER[0]...), 0x00)}, honest.KeyID, honestEnvelope.GetSignature())
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(garbage, expectedURI, goldenClock); err == nil {
		t.Fatal("trailing certificate DER must refuse")
	}
}

// TestAdmissionSignerTrustBoundary checks where trust is decided. A signer
// is trusted only when its chain verifies against the caller's bundle and
// its key is not revoked; structural validation alone never establishes
// trust. The signer certificate's validity must also cover both the
// decision clock and the lease's signed instants.
func TestAdmissionSignerTrustBoundary(t *testing.T) {
	authority := goldenAuthority(t)
	expectedURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	validity := svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_700_050_000, 0))

	intermediate, err := authority.NewIntermediate()
	if err != nil {
		t.Fatal(err)
	}
	viaIntermediate, err := intermediate.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, validity)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := viaIntermediate.SignLease(goldenPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	envelope, _, err := wire.ParseZoneAdmissionLease(raw, uint64(goldenClock.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope.GetSignerCertChain()) != 2 {
		t.Fatalf("intermediate chain length = %d, want 2", len(envelope.GetSignerCertChain()))
	}
	if _, err := wire.VerifyZoneAdmissionLeaseSigner(envelope, authority.Bundle(), expectedURI, nil, goldenClock); err != nil {
		t.Fatalf("intermediate-backed signer refused against root bundle: %v", err)
	}

	foreign, err := svidtest.NewAuthority(goldenTrustDomain, svidtest.WithClock(func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.VerifyZoneAdmissionLeaseSigner(envelope, foreign.Bundle(), expectedURI, nil, goldenClock); err == nil {
		t.Fatal("signer chaining to a different authority must refuse")
	}
	if _, err := wire.VerifyZoneAdmissionLeaseSigner(envelope, nil, expectedURI, nil, goldenClock); err == nil {
		t.Fatal("empty trust bundle must refuse")
	}
	if _, err := wire.VerifyZoneAdmissionLeaseSigner(envelope, authority.Bundle(), expectedURI, [][]byte{viaIntermediate.KeyID}, goldenClock); err == nil {
		t.Fatal("revoked signer key must refuse")
	}

	// A foreign authority minting the byte-identical expected URI still
	// fails: trust comes from chaining to the local trust bundle, never from
	// URI text.
	impostor, err := foreign.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, validity)
	if err != nil {
		t.Fatal(err)
	}
	impostorRaw, err := impostor.SignLease(goldenPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	impostorEnvelope, _, err := wire.ParseZoneAdmissionLease(impostorRaw, uint64(goldenClock.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(impostorEnvelope, expectedURI, goldenClock); err != nil {
		t.Fatalf("structural validation cannot judge trust: %v", err)
	}
	if _, err := wire.VerifyZoneAdmissionLeaseSigner(impostorEnvelope, authority.Bundle(), expectedURI, nil, goldenClock); err == nil {
		t.Fatal("impostor authority with the expected URI must refuse at the trust boundary")
	}

	// Zero-grace signer validity boundaries at the decision clock.
	signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, validity)
	if err != nil {
		t.Fatal(err)
	}
	boundaryRaw, err := signer.SignLease(goldenPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	boundaryEnvelope, _, err := wire.ParseZoneAdmissionLease(boundaryRaw, uint64(goldenClock.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(boundaryEnvelope, expectedURI, signer.Leaf.NotAfter); err == nil {
		t.Fatal("clock at signer not_after must refuse")
	}
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(boundaryEnvelope, expectedURI, signer.Leaf.NotBefore.Add(-time.Second)); err == nil {
		t.Fatal("clock before signer not_before must refuse")
	}

	// A freshly rotated signer remains usable during its first backdate
	// window. The signed issuance instant and decision clock are inside the
	// signer validity even though the fixed payload backdate begins earlier.
	freshSigner, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA,
		svidtest.WithValidity(goldenClock.Add(-30*time.Second), goldenClock.Add(23*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	freshRaw, err := freshSigner.SignLease(goldenPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	freshEnvelope, _, err := wire.ParseZoneAdmissionLease(freshRaw, uint64(goldenClock.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.VerifyZoneAdmissionLeaseSigner(freshEnvelope, authority.Bundle(), expectedURI, nil, goldenClock); err != nil {
		t.Fatalf("fresh signer refused during fixed backdate window: %v", err)
	}

	// Lease instants outside the signer certificate refuse even when the
	// payload is self-consistent.
	shortSigner, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA,
		svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_700_001_800, 0)))
	if err != nil {
		t.Fatal(err)
	}
	outsideRaw, err := shortSigner.SignLease(goldenPodPayload())
	if err != nil {
		t.Fatal(err)
	}
	outsideEnvelope, _, err := wire.ParseZoneAdmissionLease(outsideRaw, uint64(goldenClock.Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ValidateZoneAdmissionLeaseSigner(outsideEnvelope, expectedURI, goldenClock); err == nil {
		t.Fatal("lease ending after signer expiry must refuse")
	}
}

type fixedSigner struct{ public ed25519.PublicKey }

func (f fixedSigner) Public() crypto.PublicKey { return f.public }
func (f fixedSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("svidtest: fixed signer cannot sign")
}

func mustParseURI(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func flipFirstByte(raw []byte) []byte {
	out := append([]byte(nil), raw...)
	out[0] ^= 1
	return out
}
