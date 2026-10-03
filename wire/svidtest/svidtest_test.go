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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/svidtest"
)

const trustDomain = "zone-a.zone.example.com"

// fixtureTime is the fixed clock every fixture authority runs on.
var fixtureTime = time.Unix(1_700_000_060, 0).UTC()

func fixtureClock() time.Time { return fixtureTime }

func newAuthority(t *testing.T) *svidtest.Authority {
	t.Helper()
	authority, err := svidtest.NewAuthority(trustDomain, svidtest.WithClock(fixtureClock))
	if err != nil {
		t.Fatal(err)
	}
	return authority
}

func issue(t *testing.T, authority *svidtest.Authority, plane mpb.Plane, opts ...svidtest.SignerOption) *svidtest.SignerIdentity {
	t.Helper()
	signer, err := authority.IssueAdmissionSigner(plane, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

// nodePayload is a valid control-plane node lease at fixtureTime, inside
// the default signer validity.
func nodePayload() *apb.ZoneAdmissionLeasePayload {
	notBefore := uint64(fixtureTime.Unix()) - 60
	return &apb.ZoneAdmissionLeasePayload{
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
		NotBeforeUnixS:       notBefore,
		IssuedAtUnixS:        notBefore + 60,
		NotAfterUnixS:        notBefore + uint64((6 * time.Hour).Seconds()),
		NodeAdmission:        apb.NodeAdmission_NODE_ADMISSION_PROVIDER,
	}
}

// TestNewAuthorityMintsRootCA checks the root profile: a self-signed P-256
// CA for the trust domain, valid from one hour before the clock for 90
// days, that is its own bundle.
func TestNewAuthorityMintsRootCA(t *testing.T) {
	authority := newAuthority(t)
	root := authority.CACertificate()
	if authority.TrustDomain != trustDomain {
		t.Fatalf("TrustDomain = %q", authority.TrustDomain)
	}
	if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Fatalf("root is not a signing CA: IsCA %v, key usage %v", root.IsCA, root.KeyUsage)
	}
	if key, ok := root.PublicKey.(*ecdsa.PublicKey); !ok || key.Curve != elliptic.P256() {
		t.Fatalf("root key is %T, want P-256 ECDSA", root.PublicKey)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root is not self-signed: %v", err)
	}
	if !root.NotBefore.Equal(fixtureTime.Add(-time.Hour)) || !root.NotAfter.Equal(fixtureTime.Add(90*24*time.Hour)) {
		t.Fatalf("root validity %v..%v", root.NotBefore, root.NotAfter)
	}
	bundle := authority.Bundle()
	if len(bundle) != 1 || bundle[0] != root {
		t.Fatal("root bundle is not exactly the root certificate")
	}
}

// TestNewAuthorityDefaultsToWallClock checks that an authority without
// WithClock reads the wall clock, so fixtures minted without an explicit
// clock are valid now.
func TestNewAuthorityDefaultsToWallClock(t *testing.T) {
	before := time.Now().Truncate(time.Second)
	authority, err := svidtest.NewAuthority(trustDomain)
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()
	if authority.Now == nil {
		t.Fatal("authority has no clock")
	}
	notBefore := authority.CACertificate().NotBefore.Add(time.Hour)
	if notBefore.Before(before) || notBefore.After(after) {
		t.Fatalf("root not_before %v is not one hour before the wall clock", authority.CACertificate().NotBefore)
	}
}

// TestNewAuthoritiesAreIndependent checks that each authority gets a fresh
// key, so two authorities for the same trust domain do not trust each
// other's signers. Tests of untrusted signers depend on this.
func TestNewAuthoritiesAreIndependent(t *testing.T) {
	a, b := newAuthority(t), newAuthority(t)
	if bytes.Equal(a.CACertificate().RawSubjectPublicKeyInfo, b.CACertificate().RawSubjectPublicKeyInfo) {
		t.Fatal("two authorities share a key")
	}
	if a.CACertificate().SerialNumber.Cmp(b.CACertificate().SerialNumber) == 0 {
		t.Fatal("two authorities share a serial number")
	}
	signer := issue(t, b, mpb.Plane_PLANE_DATA)
	roots := x509.NewCertPool()
	roots.AddCert(a.CACertificate())
	if _, err := signer.Leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: fixtureTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		t.Fatal("a signer from one authority verifies under another")
	}
}

// TestAuthorityReportsUnencodableValidity checks that a clock placing a CA
// validity outside what X.509 can encode (after the year 9999) is
// reported as an error from NewAuthority and NewIntermediate, not as a
// panic or a half-built authority.
func TestAuthorityReportsUnencodableValidity(t *testing.T) {
	lateClock := func() time.Time { return time.Date(9999, 12, 1, 0, 0, 0, 0, time.UTC) }
	if authority, err := svidtest.NewAuthority(trustDomain, svidtest.WithClock(lateClock)); err == nil || authority != nil {
		t.Fatal("root with an unencodable validity was minted")
	}
	authority := newAuthority(t)
	authority.Now = lateClock
	if intermediate, err := authority.NewIntermediate(); err == nil || intermediate != nil {
		t.Fatal("intermediate with an unencodable validity was minted")
	}
}

// TestNewIntermediateChainsToRoot checks the intermediate profile and the
// transmitted chain: an intermediate is a CA signed by its parent, keeps
// the root as the only trust anchor, and signers beneath it carry every
// intermediate, nearest first, but never the root.
func TestNewIntermediateChainsToRoot(t *testing.T) {
	root := newAuthority(t)
	first, err := root.NewIntermediate()
	if err != nil {
		t.Fatal(err)
	}
	second, err := first.NewIntermediate()
	if err != nil {
		t.Fatal(err)
	}
	for _, intermediate := range []*svidtest.Authority{first, second} {
		certificate := intermediate.CACertificate()
		if !certificate.IsCA || certificate.KeyUsage != x509.KeyUsageCertSign {
			t.Fatalf("intermediate is not a signing CA: key usage %v", certificate.KeyUsage)
		}
		if !certificate.NotBefore.Equal(fixtureTime.Add(-time.Hour)) || !certificate.NotAfter.Equal(fixtureTime.Add(60*24*time.Hour)) {
			t.Fatalf("intermediate validity %v..%v", certificate.NotBefore, certificate.NotAfter)
		}
		if intermediate.TrustDomain != trustDomain || !intermediate.Now().Equal(fixtureTime) {
			t.Fatal("intermediate does not share the parent's trust domain and clock")
		}
		if bundle := intermediate.Bundle(); len(bundle) != 1 || bundle[0] != root.CACertificate() {
			t.Fatal("intermediate bundle is not the root alone")
		}
	}
	if err := first.CACertificate().CheckSignatureFrom(root.CACertificate()); err != nil {
		t.Fatalf("first intermediate not signed by root: %v", err)
	}
	if err := second.CACertificate().CheckSignatureFrom(first.CACertificate()); err != nil {
		t.Fatalf("second intermediate not signed by first: %v", err)
	}

	signer := issue(t, second, mpb.Plane_PLANE_DATA)
	want := [][]byte{signer.Leaf.Raw, second.CACertificate().Raw, first.CACertificate().Raw}
	if !slices.EqualFunc(signer.ChainDER, want, bytes.Equal) {
		t.Fatalf("chain has %d entries, want leaf, second, first", len(signer.ChainDER))
	}
	if _, err := wire.ValidateAdmissionSignerChainDER(signer.ChainDER, signer.URI); err != nil {
		t.Fatalf("intermediate-issued signer is out of profile: %v", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range signer.ChainDER[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		intermediates.AddCert(certificate)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root.Bundle()[0])
	if _, err := signer.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, Intermediates: intermediates, CurrentTime: fixtureTime,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Fatalf("signer does not chain to the root through its transmitted chain: %v", err)
	}
}

// TestIssueAdmissionSignerDefaultProfile checks that a default signer for
// each plane is the in-profile SVID the package documents: a P-256 leaf
// valid from one minute before the clock for 12 hours, carrying the
// plane's signer URI as its only SAN, with the key ID derived from its
// SPKI, and that wire's own signer validation accepts it.
func TestIssueAdmissionSignerDefaultProfile(t *testing.T) {
	authority := newAuthority(t)
	for _, plane := range []mpb.Plane{mpb.Plane_PLANE_CONTROL, mpb.Plane_PLANE_DATA} {
		t.Run(plane.String(), func(t *testing.T) {
			signer := issue(t, authority, plane)
			wantURI, err := wire.AdmissionSignerURIForPlane(trustDomain, plane)
			if err != nil {
				t.Fatal(err)
			}
			leaf := signer.Leaf
			if signer.URI != wantURI || len(leaf.URIs) != 1 || leaf.URIs[0].String() != wantURI {
				t.Fatalf("signer URI %q, leaf URIs %v, want %q", signer.URI, leaf.URIs, wantURI)
			}
			if len(leaf.DNSNames)+len(leaf.EmailAddresses)+len(leaf.IPAddresses) != 0 {
				t.Fatal("leaf carries a SAN besides its URI")
			}
			if key, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok || key.Curve != elliptic.P256() {
				t.Fatalf("leaf key is %T, want P-256 ECDSA", leaf.PublicKey)
			}
			if leaf.IsCA || leaf.KeyUsage != x509.KeyUsageDigitalSignature {
				t.Fatalf("leaf IsCA %v, key usage %v", leaf.IsCA, leaf.KeyUsage)
			}
			if !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}) {
				t.Fatalf("leaf extended key usage %v", leaf.ExtKeyUsage)
			}
			if !leaf.NotBefore.Equal(fixtureTime.Add(-time.Minute)) || !leaf.NotAfter.Equal(fixtureTime.Add(12*time.Hour)) {
				t.Fatalf("leaf validity %v..%v", leaf.NotBefore, leaf.NotAfter)
			}
			if leaf.NotAfter.Sub(leaf.NotBefore) > apb.MaxAdmissionSignerLifetime {
				t.Fatal("default signer exceeds the admission signer lifetime cap")
			}
			if err := leaf.CheckSignatureFrom(authority.CACertificate()); err != nil {
				t.Fatalf("leaf not issued by the authority: %v", err)
			}
			if len(signer.ChainDER) != 1 || !bytes.Equal(signer.ChainDER[0], leaf.Raw) {
				t.Fatal("root-issued signer chain is not the leaf alone")
			}
			keyID := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if !bytes.Equal(signer.KeyID, keyID[:]) {
				t.Fatal("key ID is not SHA-256 of the leaf SPKI")
			}
			if public, ok := signer.Key.Public().(*ecdsa.PublicKey); !ok || !public.Equal(leaf.PublicKey) {
				t.Fatal("signer key does not match the leaf")
			}
			facts, err := wire.ValidateAdmissionSignerChainDER(signer.ChainDER, wantURI)
			if err != nil {
				t.Fatalf("default signer is out of profile: %v", err)
			}
			if !bytes.Equal(facts.KeyID, signer.KeyID) {
				t.Fatal("wire derives a different key ID")
			}
		})
	}
}

// TestIssueAdmissionSignerRefusesBadInput checks that an unknown plane, an
// invalid trust domain, an unparsable URI, an issuance the x509 package
// refuses, and a certificate that does not parse back are reported as
// errors rather than panics or partial identities.
func TestIssueAdmissionSignerRefusesBadInput(t *testing.T) {
	authority := newAuthority(t)
	if signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_UNSPECIFIED); err == nil || signer != nil {
		t.Fatal("unspecified plane accepted")
	}
	badDomain, err := svidtest.NewAuthority("Zone A", svidtest.WithClock(fixtureClock))
	if err != nil {
		t.Fatal(err)
	}
	if signer, err := badDomain.IssueAdmissionSigner(mpb.Plane_PLANE_DATA); err == nil || signer != nil {
		t.Fatal("invalid trust domain accepted")
	}
	if signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, svidtest.WithURI("spiffe://%zz")); err == nil || signer != nil {
		t.Fatal("unparsable URI accepted")
	}
	negativeSerial := svidtest.WithTemplate(func(c *x509.Certificate) { c.SerialNumber = big.NewInt(-1) })
	if signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, negativeSerial); err == nil || signer != nil {
		t.Fatal("certificate with a negative serial number issued")
	}
	if signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, svidtest.WithKey(unsupportedKey{})); err == nil || signer != nil {
		t.Fatal("certificate for an unsupported key type issued")
	}
	unparsableSAN := svidtest.WithTemplate(func(c *x509.Certificate) {
		c.URIs = []*url.URL{{Scheme: "spiffe", Host: "a..b", Path: "/service/admission-signer/data"}}
	})
	if signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA, unparsableSAN); err == nil || signer != nil {
		t.Fatal("certificate that does not parse back was returned")
	}
}

// TestSignerOptions checks each option on its own and in order: options
// apply in the order given, so WithLifetime after WithValidity measures
// from the new not_before.
func TestSignerOptions(t *testing.T) {
	authority := newAuthority(t)
	notBefore := fixtureTime.Add(-2 * time.Hour)
	notAfter := fixtureTime.Add(3 * time.Hour)

	lifetime := issue(t, authority, mpb.Plane_PLANE_DATA, svidtest.WithLifetime(2*time.Hour))
	if !lifetime.Leaf.NotAfter.Equal(fixtureTime.Add(-time.Minute).Add(2 * time.Hour)) {
		t.Errorf("WithLifetime: not_after %v", lifetime.Leaf.NotAfter)
	}
	validity := issue(t, authority, mpb.Plane_PLANE_DATA, svidtest.WithValidity(notBefore, notAfter))
	if !validity.Leaf.NotBefore.Equal(notBefore) || !validity.Leaf.NotAfter.Equal(notAfter) {
		t.Errorf("WithValidity: %v..%v", validity.Leaf.NotBefore, validity.Leaf.NotAfter)
	}
	ordered := issue(t, authority, mpb.Plane_PLANE_DATA, svidtest.WithValidity(notBefore, notAfter), svidtest.WithLifetime(time.Hour))
	if !ordered.Leaf.NotAfter.Equal(notBefore.Add(time.Hour)) {
		t.Errorf("WithValidity then WithLifetime: not_after %v", ordered.Leaf.NotAfter)
	}

	const otherURI = "spiffe://zone-b.zone.example.com/service/admission-signer/data"
	uri := issue(t, authority, mpb.Plane_PLANE_DATA, svidtest.WithURI(otherURI))
	if uri.URI != otherURI || uri.Leaf.URIs[0].String() != otherURI {
		t.Errorf("WithURI: identity %q, leaf %v", uri.URI, uri.Leaf.URIs)
	}

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key := issue(t, authority, mpb.Plane_PLANE_DATA, svidtest.WithKey(p384))
	if public, ok := key.Leaf.PublicKey.(*ecdsa.PublicKey); !ok || public.Curve != elliptic.P384() || key.Key != crypto.Signer(p384) {
		t.Errorf("WithKey: leaf key %T", key.Leaf.PublicKey)
	}

	explicit, err := url.Parse("spiffe://" + trustDomain + "/service/other")
	if err != nil {
		t.Fatal(err)
	}
	template := issue(t, authority, mpb.Plane_PLANE_DATA, svidtest.WithTemplate(func(c *x509.Certificate) {
		c.DNSNames = []string{"signer.example.com"}
		c.URIs = []*url.URL{explicit}
	}))
	if !slices.Equal(template.Leaf.DNSNames, []string{"signer.example.com"}) {
		t.Errorf("WithTemplate: DNS names %v", template.Leaf.DNSNames)
	}
	if len(template.Leaf.URIs) != 1 || template.Leaf.URIs[0].String() != explicit.String() {
		t.Errorf("WithTemplate: a template that sets URIs was overridden: %v", template.Leaf.URIs)
	}
}

// TestOutOfProfileSignersAreRefusedByWire checks the purpose of the
// options: each one can push a signer outside the admission signer
// profile, and wire's signer validation then refuses it with
// ErrAdmissionSignerProfile.
func TestOutOfProfileSignersAreRefusedByWire(t *testing.T) {
	authority := newAuthority(t)
	dataURI, err := wire.AdmissionSignerURIForPlane(trustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, option := range map[string]svidtest.SignerOption{
		"P-384 key":     svidtest.WithKey(p384),
		"CA leaf":       svidtest.WithTemplate(func(c *x509.Certificate) { c.IsCA, c.KeyUsage = true, c.KeyUsage|x509.KeyUsageCertSign }),
		"DNS SAN":       svidtest.WithTemplate(func(c *x509.Certificate) { c.DNSNames = []string{"signer.example.com"} }),
		"other domain":  svidtest.WithURI("spiffe://zone-b.zone.example.com/service/admission-signer/data"),
		"over lifetime": svidtest.WithLifetime(apb.MaxAdmissionSignerLifetime + time.Second),
	} {
		signer := issue(t, authority, mpb.Plane_PLANE_DATA, option)
		if _, err := wire.ValidateAdmissionSignerChainDER(signer.ChainDER, dataURI); !errors.Is(err, wire.ErrAdmissionSignerProfile) {
			t.Errorf("%s: err = %v, want ErrAdmissionSignerProfile", name, err)
		}
	}
}

// TestSignLeaseProducesVerifiableEnvelope checks the end-to-end use: a
// lease signed by a default signer parses canonically and passes the full
// trust-boundary verification against the authority's bundle.
func TestSignLeaseProducesVerifiableEnvelope(t *testing.T) {
	authority := newAuthority(t)
	signer := issue(t, authority, mpb.Plane_PLANE_CONTROL)
	raw, err := signer.SignLease(nodePayload())
	if err != nil {
		t.Fatal(err)
	}
	envelope, payload, err := wire.ParseZoneAdmissionLease(raw, uint64(fixtureTime.Unix()))
	if err != nil {
		t.Fatalf("signed envelope does not parse: %v", err)
	}
	if payload.GetNodeId() != "node-a" || !bytes.Equal(envelope.GetSignerKeyId(), signer.KeyID) {
		t.Fatal("envelope does not carry the payload and signer key ID")
	}
	if !slices.EqualFunc(envelope.GetSignerCertChain(), signer.ChainDER, bytes.Equal) {
		t.Fatal("envelope does not carry the signer chain")
	}
	facts, err := wire.VerifyZoneAdmissionLeaseSigner(envelope, authority.Bundle(), signer.URI, nil, fixtureTime)
	if err != nil {
		t.Fatalf("signed envelope does not verify: %v", err)
	}
	if facts.URI != signer.URI {
		t.Fatalf("verified signer URI %q", facts.URI)
	}
}

// TestSignLeaseRefusesInvalidPayload checks that SignLease validates
// before signing, while SignLeasePayloadBytes signs exactly what it is
// given so negative tests can build leases a verifier must refuse.
func TestSignLeaseRefusesInvalidPayload(t *testing.T) {
	authority := newAuthority(t)
	signer := issue(t, authority, mpb.Plane_PLANE_CONTROL)
	invalid := nodePayload()
	invalid.Version = 1
	if raw, err := signer.SignLease(invalid); err == nil || raw != nil {
		t.Fatal("SignLease signed an invalid payload")
	}
	if raw, err := signer.SignLease(nil); err == nil || raw != nil {
		t.Fatal("SignLease signed an absent payload")
	}
	if raw, err := signer.SignLeasePayloadBytes(nil); err == nil || raw != nil {
		t.Fatal("SignLeasePayloadBytes produced an envelope for an empty payload")
	}
	unsigned := &svidtest.SignerIdentity{Key: unsupportedKey{}, KeyID: signer.KeyID, ChainDER: signer.ChainDER}
	if raw, err := unsigned.SignLeasePayloadBytes([]byte{0x08, 0x03}); err == nil || raw != nil {
		t.Fatal("a key that cannot sign produced an envelope")
	}
}

// unsupportedKey is a crypto.Signer with a key type neither x509 nor the
// lease signer accepts, and which cannot sign.
type unsupportedKey struct{}

func (unsupportedKey) Public() crypto.PublicKey { return ed25519.PublicKey(nil) }

func (unsupportedKey) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("unsupported key cannot sign")
}
