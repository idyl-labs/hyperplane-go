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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
)

// Typed signer refusal classes. Every signer judgment fails with exactly one
// of these by name, so consumers and conformance fixtures never classify by
// message text.
var (
	// ErrAdmissionSignerProfile names a signer chain whose shape, leaf
	// profile, URI, key type, lifetime, or key ID is outside the admission
	// signer profile.
	ErrAdmissionSignerProfile = errors.New("wire: admission signer outside the v3 profile")
	// ErrAdmissionSignerValidity names a signer outside its own validity
	// interval at the decision clock.
	ErrAdmissionSignerValidity = errors.New("wire: admission signer outside its validity interval")
	// ErrAdmissionSignerUntrusted names a signer that does not chain to the
	// verifier's current local trust bundle.
	ErrAdmissionSignerUntrusted = errors.New("wire: admission signer does not chain to the local trust bundle")
	// ErrAdmissionSignerRevoked names a signer key ID present in the
	// verifier's revocation set.
	ErrAdmissionSignerRevoked = errors.New("wire: admission signer key is revoked")
	// ErrAdmissionLeaseOutsideSigner names a lease whose instants fall
	// outside the signer certificate's validity interval.
	ErrAdmissionLeaseOutsideSigner = errors.New("wire: lease validity is outside admission signer validity")
)

// admission_svid.go: the admission signer profile. Leases are signed by
// dedicated X.509-SVID identities issued by the zone trust domain. A verifier
// derives exactly one expected signer URI from its own configured trust
// domain and fabric plane, never from lease content, and requires the
// presented leaf to match it byte for byte. Trust-anchored verification
// additionally chains the presented certificates to the verifier's current
// local trust bundle. There is no pinned admission root, no delegated-signer
// certificate profile, and no admission-specific EKU.

// AdmissionSignerFacts is the typed result of signer validation: every fact
// a caller needs (leaf, canonical URI, public key, key ID, validity bounds)
// from one validation path, so consumers never re-derive them differently.
type AdmissionSignerFacts struct {
	Leaf  *x509.Certificate
	Chain []*x509.Certificate // presented chain, leaf first
	URI   string
	// PublicKey is the leaf ECDSA P-256 public key.
	PublicKey      *ecdsa.PublicKey
	KeyID          []byte
	NotBeforeUnixS uint64
	NotAfterUnixS  uint64
}

// AdmissionSignerURIForPlane derives the only SPIFFE ID permitted to sign
// admission leases for one fabric plane in one zone trust domain. Each
// plane has its own signer identity, so a signer for one plane can never
// admit an endpoint to the other.
func AdmissionSignerURIForPlane(trustDomain string, plane mpb.Plane) (string, error) {
	if err := ValidateTrustDomain(trustDomain); err != nil {
		return "", err
	}
	switch plane {
	case mpb.Plane_PLANE_CONTROL:
		return "spiffe://" + trustDomain + apb.ControlPlaneAdmissionSignerPath, nil
	case mpb.Plane_PLANE_DATA:
		return "spiffe://" + trustDomain + apb.DataPlaneAdmissionSignerPath, nil
	default:
		return "", fmt.Errorf("wire: no admission signer authority for plane %d", plane)
	}
}

// AdmissionSignerKeyID returns SHA-256 over DER SubjectPublicKeyInfo. The
// same 32 bytes appear in the lease envelope's signer_key_id.
func AdmissionSignerKeyID(certificate *x509.Certificate) ([]byte, error) {
	if certificate == nil || len(certificate.RawSubjectPublicKeyInfo) == 0 {
		return nil, fmt.Errorf("wire: admission signer certificate has no SPKI")
	}
	digest := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return digest[:], nil
}

// ValidateExpectedAdmissionSignerURI refuses configuration values that are
// not canonical admission signer SPIFFE IDs for a known fabric plane. The
// returned plane names the authority the URI carries.
func ValidateExpectedAdmissionSignerURI(expected string) (mpb.Plane, error) {
	u, err := url.Parse(expected)
	if err != nil || u.String() != expected {
		return mpb.Plane_PLANE_UNSPECIFIED, fmt.Errorf("wire: malformed admission signer URI")
	}
	if u.Scheme != "spiffe" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.Port() != "" || u.RawPath != "" || u.Host == "" {
		return mpb.Plane_PLANE_UNSPECIFIED, fmt.Errorf("wire: malformed admission signer URI")
	}
	if err := ValidateTrustDomain(u.Host); err != nil {
		return mpb.Plane_PLANE_UNSPECIFIED, err
	}
	switch u.Path {
	case apb.ControlPlaneAdmissionSignerPath:
		return mpb.Plane_PLANE_CONTROL, nil
	case apb.DataPlaneAdmissionSignerPath:
		return mpb.Plane_PLANE_DATA, nil
	default:
		return mpb.Plane_PLANE_UNSPECIFIED, fmt.Errorf("wire: URI is not an admission signer identity")
	}
}

// ValidateZoneAdmissionLeaseSigner performs the complete structural signer
// judgment for callers that deliberately do not own trust anchors (for
// example, an endpoint checking a lease before presenting it): bounded
// chain shape, X.509-SVID leaf profile, exact expected URI, key-ID
// equality, canonical signature verification, signer validity at the
// decision clock, and lease times within the signer's validity. It does
// not chain the signer to a trust bundle; the edge's configured trust
// remains the authoritative admission decision.
func ValidateZoneAdmissionLeaseSigner(envelope *apb.ZoneAdmissionLease, expectedSignerURI string, now time.Time) (*AdmissionSignerFacts, error) {
	if err := validateZoneAdmissionLeaseEnvelope(envelope); err != nil {
		return nil, err
	}
	if now.IsZero() {
		return nil, fmt.Errorf("wire: admission signer verification clock absent")
	}
	facts, err := validateAdmissionSignerChain(envelope.GetSignerCertChain(), expectedSignerURI)
	if err != nil {
		return nil, err
	}
	if err := admissionSignerUsableAt(facts, now); err != nil {
		return nil, err
	}
	if !bytes.Equal(envelope.GetSignerKeyId(), facts.KeyID) {
		return nil, fmt.Errorf("%w: key id does not match certificate SPKI", ErrAdmissionSignerProfile)
	}
	if err := verifyLeaseSignatureP256(facts.PublicKey, envelope.GetPayload(), envelope.GetSignature()); err != nil {
		return nil, err
	}
	if err := leaseTimesWithinSigner(envelope, facts); err != nil {
		return nil, err
	}
	return facts, nil
}

// VerifyZoneAdmissionLeaseSigner applies the complete trust-boundary
// decision: everything ValidateZoneAdmissionLeaseSigner enforces, plus
// revocation of the signer key ID and cryptographic chain validation from
// the presented leaf through any presented intermediates to the caller's
// current local trust bundle. The bundle is the verifier's live local zone
// trust material; federated bundles, payload-provided roots, and statically
// pinned anchors must never be passed here.
func VerifyZoneAdmissionLeaseSigner(envelope *apb.ZoneAdmissionLease, bundle []*x509.Certificate, expectedSignerURI string, revokedKeyIDs [][]byte, now time.Time) (*AdmissionSignerFacts, error) {
	facts, err := ValidateZoneAdmissionLeaseSigner(envelope, expectedSignerURI, now)
	if err != nil {
		return nil, err
	}
	for _, revoked := range revokedKeyIDs {
		if bytes.Equal(facts.KeyID, revoked) {
			return nil, ErrAdmissionSignerRevoked
		}
	}
	if len(bundle) == 0 {
		return nil, fmt.Errorf("%w: trust bundle absent", ErrAdmissionSignerUntrusted)
	}
	roots := x509.NewCertPool()
	for _, anchor := range bundle {
		if anchor == nil {
			return nil, fmt.Errorf("%w: trust bundle contains a nil certificate", ErrAdmissionSignerUntrusted)
		}
		roots.AddCert(anchor)
	}
	intermediates := x509.NewCertPool()
	for _, certificate := range facts.Chain[1:] {
		intermediates.AddCert(certificate)
	}
	if _, err := facts.Leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAdmissionSignerUntrusted, err)
	}
	return facts, nil
}

// ValidateAdmissionSignerChainDER parses and validates the bounded
// leaf-first signer chain against the exact expected signer URI, returning
// typed signer facts. Producers use it to validate a freshly sampled signer
// identity before minting; consumers use it inside envelope validation.
func ValidateAdmissionSignerChainDER(chainDER [][]byte, expectedSignerURI string) (*AdmissionSignerFacts, error) {
	return validateAdmissionSignerChain(chainDER, expectedSignerURI)
}

// validateAdmissionSignerChain parses and validates the bounded leaf-first
// chain carried by a lease envelope against the exact expected signer URI.
func validateAdmissionSignerChain(chainDER [][]byte, expectedSignerURI string) (*AdmissionSignerFacts, error) {
	if _, err := ValidateExpectedAdmissionSignerURI(expectedSignerURI); err != nil {
		return nil, err
	}
	if len(chainDER) == 0 || len(chainDER) > apb.MaxSignerChainLength {
		return nil, fmt.Errorf("%w: chain length %d", ErrAdmissionSignerProfile, len(chainDER))
	}
	total := 0
	chain := make([]*x509.Certificate, 0, len(chainDER))
	for i, certDER := range chainDER {
		if len(certDER) == 0 || len(certDER) > apb.MaxSignerCertificateDER {
			return nil, fmt.Errorf("%w: certificate %d size %d", ErrAdmissionSignerProfile, i, len(certDER))
		}
		total += len(certDER)
		certificate, err := x509.ParseCertificate(certDER)
		if err != nil {
			return nil, fmt.Errorf("%w: parse certificate %d: %v", ErrAdmissionSignerProfile, i, err)
		}
		chain = append(chain, certificate)
	}
	if total > apb.MaxSignerChainDERBytes {
		return nil, fmt.Errorf("%w: chain is %d DER bytes, maximum %d", ErrAdmissionSignerProfile, total, apb.MaxSignerChainDERBytes)
	}
	leaf := chain[0]
	if err := validateAdmissionSignerLeaf(leaf, expectedSignerURI); err != nil {
		return nil, err
	}
	for i, intermediate := range chain[1:] {
		if !intermediate.BasicConstraintsValid || !intermediate.IsCA {
			return nil, fmt.Errorf("%w: chain certificate %d is not a CA", ErrAdmissionSignerProfile, i+1)
		}
	}
	keyID, err := AdmissionSignerKeyID(leaf)
	if err != nil {
		return nil, err
	}
	notBefore := leaf.NotBefore.Unix()
	notAfter := leaf.NotAfter.Unix()
	if notBefore < 0 || notAfter < 0 {
		return nil, fmt.Errorf("%w: validity precedes the epoch", ErrAdmissionSignerProfile)
	}
	return &AdmissionSignerFacts{
		Leaf:           leaf,
		Chain:          chain,
		URI:            leaf.URIs[0].String(),
		PublicKey:      leaf.PublicKey.(*ecdsa.PublicKey),
		KeyID:          keyID,
		NotBeforeUnixS: uint64(notBefore),
		NotAfterUnixS:  uint64(notAfter),
	}, nil
}

// validateAdmissionSignerLeaf enforces the bounded X.509-SVID signing
// profile: ECDSA P-256 key, non-CA, digital signature permitted, no
// certificate-authority key usages, only TLS peer EKUs, no unhandled
// critical extensions, exactly one canonical SPIFFE URI SAN equal to the
// expected signer identity, and an encoded lifetime inside the cap.
func validateAdmissionSignerLeaf(leaf *x509.Certificate, expectedSignerURI string) error {
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve != elliptic.P256() {
		return fmt.Errorf("%w: key must be ECDSA P-256", ErrAdmissionSignerProfile)
	}
	if !leaf.BasicConstraintsValid || leaf.IsCA {
		return fmt.Errorf("%w: must be a non-CA with valid basic constraints", ErrAdmissionSignerProfile)
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("%w: must permit digital signature", ErrAdmissionSignerProfile)
	}
	if leaf.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return fmt.Errorf("%w: must not carry certificate-authority key usage", ErrAdmissionSignerProfile)
	}
	for _, eku := range leaf.ExtKeyUsage {
		if eku != x509.ExtKeyUsageClientAuth && eku != x509.ExtKeyUsageServerAuth {
			return fmt.Errorf("%w: carries a non-SVID extended key usage", ErrAdmissionSignerProfile)
		}
	}
	if len(leaf.UnknownExtKeyUsage) != 0 {
		return fmt.Errorf("%w: carries an unknown extended key usage", ErrAdmissionSignerProfile)
	}
	if len(leaf.UnhandledCriticalExtensions) != 0 {
		return fmt.Errorf("%w: carries unhandled critical extensions", ErrAdmissionSignerProfile)
	}
	if len(leaf.URIs) != 1 || len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.EmailAddresses) != 0 {
		return fmt.Errorf("%w: must carry exactly one URI SAN", ErrAdmissionSignerProfile)
	}
	uri := leaf.URIs[0].String()
	if uri != expectedSignerURI || !strings.HasPrefix(uri, "spiffe://") {
		return fmt.Errorf("%w: URI %q, want %q", ErrAdmissionSignerProfile, uri, expectedSignerURI)
	}
	if !leaf.NotAfter.After(leaf.NotBefore) {
		return fmt.Errorf("%w: validity interval is empty", ErrAdmissionSignerProfile)
	}
	if leaf.NotAfter.Sub(leaf.NotBefore) > apb.MaxAdmissionSignerLifetime {
		return fmt.Errorf("%w: lifetime exceeds %s", ErrAdmissionSignerProfile, apb.MaxAdmissionSignerLifetime)
	}
	return nil
}

// ValidateTrustDomain returns an error unless trustDomain is a SPIFFE trust
// domain in the form admission accepts: at most 253 bytes, with no
// surrounding white space, made of dot-separated labels of 1 to 63 bytes,
// each of lowercase ASCII letters, digits and hyphens, neither starting
// nor ending with a hyphen.
func ValidateTrustDomain(trustDomain string) error {
	if trustDomain == "" || len(trustDomain) > 253 || strings.TrimSpace(trustDomain) != trustDomain {
		return fmt.Errorf("wire: invalid admission trust domain %q", trustDomain)
	}
	for _, label := range strings.Split(trustDomain, ".") {
		if len(label) > 63 || !isDNSLabel(label) {
			return fmt.Errorf("wire: invalid admission trust domain %q", trustDomain)
		}
	}
	return nil
}

// admissionSignerUsableAt applies the zero-grace signer validity boundary at
// the decision clock: not_before <= now < not_after.
func admissionSignerUsableAt(facts *AdmissionSignerFacts, now time.Time) error {
	if now.Before(facts.Leaf.NotBefore) || !now.Before(facts.Leaf.NotAfter) {
		return ErrAdmissionSignerValidity
	}
	return nil
}

// leaseTimesWithinSigner requires the authoritative issuance instant and
// deadline to lie inside the signer certificate's validity interval. The
// payload's fixed clock-skew backdate may precede a freshly rotated signer's
// not-before; the signer is still required to be valid at both issuance and
// the verifier's decision clock.
func leaseTimesWithinSigner(envelope *apb.ZoneAdmissionLease, facts *AdmissionSignerFacts) error {
	var payload apb.ZoneAdmissionLeasePayload
	if err := UnmarshalCanonical(envelope.GetPayload(), &payload, apb.MaxLeasePayloadBytes, "lease payload"); err != nil {
		return err
	}
	if payload.GetIssuedAtUnixS() < facts.NotBeforeUnixS ||
		payload.GetIssuedAtUnixS() >= facts.NotAfterUnixS ||
		payload.GetNotAfterUnixS() > facts.NotAfterUnixS {
		return ErrAdmissionLeaseOutsideSigner
	}
	return nil
}
