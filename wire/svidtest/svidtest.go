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

// Package svidtest mints an in-memory X.509-SVID test PKI for admission
// lease tests: a P-256 CA for one trust domain, optional intermediate CAs,
// and admission signer SVIDs that sign ZoneAdmissionLease envelopes. Tests
// build admission fixtures from this one implementation instead of
// re-deriving the certificate profile.
//
// It is test support only. Keys are generated per call and held in
// memory, lifetimes are parameters, it issues nothing outside the calling
// process, and no real trust bundle trusts anything it mints.
package svidtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
)

// Authority is one test CA for a trust domain. A root Authority stands for
// the zone trust bundle; an intermediate Authority issues beneath it.
// Now is the clock that sets validity for everything the authority
// mints.
type Authority struct {
	TrustDomain string
	Now         func() time.Time

	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	parents     []*x509.Certificate // intermediates from this CA back to, but not including, the root
	root        *Authority
}

// AuthorityOption configures an Authority before its certificate is
// minted.
type AuthorityOption func(*Authority)

// WithClock sets the authority's clock. The CA validity and every default
// signer validity derive from it, so fixtures can be minted at a fixed
// instant.
func WithClock(now func() time.Time) AuthorityOption {
	return func(a *Authority) { a.Now = now }
}

// NewAuthority mints a self-signed P-256 root CA for one trust domain,
// valid from one hour before the clock's current time for 90 days.
func NewAuthority(trustDomain string, opts ...AuthorityOption) (*Authority, error) {
	authority := &Authority{TrustDomain: trustDomain, Now: time.Now}
	authority.root = authority
	for _, opt := range opts {
		opt(authority)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "svidtest CA " + trustDomain},
		NotBefore:             authority.Now().Add(-time.Hour),
		NotAfter:              authority.Now().Add(90 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	authority.certificate = certificate
	authority.key = key
	return authority, nil
}

// NewIntermediate mints a child CA that shares the parent's trust domain
// and clock. Signers issued by an intermediate carry it, and any
// intermediates above it, in their transmitted chain; only the root
// belongs in the trust bundle.
func (a *Authority) NewIntermediate() (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "svidtest intermediate " + a.TrustDomain},
		NotBefore:             a.Now().Add(-time.Hour),
		NotAfter:              a.Now().Add(60 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{
		TrustDomain: a.TrustDomain,
		Now:         a.Now,
		certificate: certificate,
		key:         key,
		parents:     append([]*x509.Certificate{certificate}, a.parents...),
		root:        a.root,
	}, nil
}

// Bundle returns the trust anchors a verifier installs: the root CA
// alone, whichever authority in the hierarchy it is called on.
func (a *Authority) Bundle() []*x509.Certificate {
	return []*x509.Certificate{a.root.certificate}
}

// CACertificate returns this authority's own CA certificate.
func (a *Authority) CACertificate() *x509.Certificate { return a.certificate }

// SignerIdentity is one minted admission signer SVID: the chain it
// transmits (leaf first, then any intermediates), the parsed leaf, its
// private key, the key ID derived from the leaf, and its SPIFFE URI.
type SignerIdentity struct {
	ChainDER [][]byte
	Leaf     *x509.Certificate
	Key      crypto.Signer
	KeyID    []byte
	URI      string
}

// SignerTemplate is the shape of a signer SVID before issuance. Each
// SignerOption may change it.
type SignerTemplate struct {
	URI       string
	NotBefore time.Time
	NotAfter  time.Time
	Template  *x509.Certificate // URI SAN set from URI after options run, unless an option set URIs
	Key       crypto.Signer     // defaults to a fresh P-256 key
}

// SignerOption changes a SignerTemplate before issuance. Negative tests use
// options to mint signers that deliberately violate the signer profile.
type SignerOption func(*SignerTemplate)

// WithLifetime sets NotAfter = NotBefore + lifetime.
func WithLifetime(lifetime time.Duration) SignerOption {
	return func(s *SignerTemplate) { s.NotAfter = s.NotBefore.Add(lifetime) }
}

// WithValidity sets the exact validity interval.
func WithValidity(notBefore, notAfter time.Time) SignerOption {
	return func(s *SignerTemplate) { s.NotBefore, s.NotAfter = notBefore, notAfter }
}

// WithURI overrides the SPIFFE URI SAN.
func WithURI(uri string) SignerOption {
	return func(s *SignerTemplate) { s.URI = uri }
}

// WithKey issues the SVID for the given key instead of a fresh P-256 key,
// for example to build a signer on the wrong curve.
func WithKey(key crypto.Signer) SignerOption {
	return func(s *SignerTemplate) { s.Key = key }
}

// WithTemplate gives direct access to the certificate template, for
// out-of-profile shapes such as a CA bit, other key usages, extra SANs, or
// extra extended key usages.
func WithTemplate(mutate func(*x509.Certificate)) SignerOption {
	return func(s *SignerTemplate) { mutate(s.Template) }
}

// IssueAdmissionSigner mints an admission signer SVID for one fabric
// plane, carrying the signer URI that wire.AdmissionSignerURIForPlane
// derives for the plane in this trust domain. By default the SVID is
// in-profile: a P-256 leaf valid from one minute before the clock's
// current time for 12 hours. Options can take it out of profile.
func (a *Authority) IssueAdmissionSigner(plane mpb.Plane, opts ...SignerOption) (*SignerIdentity, error) {
	uri, err := wire.AdmissionSignerURIForPlane(a.TrustDomain, plane)
	if err != nil {
		return nil, err
	}
	now := a.Now()
	shape := &SignerTemplate{
		URI:       uri,
		NotBefore: now.Add(-time.Minute),
		NotAfter:  now.Add(12 * time.Hour),
		Template: &x509.Certificate{
			SerialNumber:          serial(),
			Subject:               pkix.Name{CommonName: "svidtest admission signer"},
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
		},
	}
	for _, opt := range opts {
		opt(shape)
	}
	if shape.Key == nil {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		shape.Key = key
	}
	template := shape.Template
	template.NotBefore = shape.NotBefore
	template.NotAfter = shape.NotAfter
	if template.URIs == nil {
		parsed, err := url.Parse(shape.URI)
		if err != nil {
			return nil, fmt.Errorf("svidtest: signer URI: %w", err)
		}
		template.URIs = []*url.URL{parsed}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, shape.Key.Public(), a.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	chainDER := [][]byte{der}
	for _, parent := range a.parents {
		chainDER = append(chainDER, parent.Raw)
	}
	keyID, err := wire.AdmissionSignerKeyID(leaf)
	if err != nil {
		return nil, err
	}
	return &SignerIdentity{ChainDER: chainDER, Leaf: leaf, Key: shape.Key, KeyID: keyID, URI: shape.URI}, nil
}

// SignLease canonically marshals payload, signs it under the
// zone-admission-lease/3 signature domain, and returns the canonical
// ZoneAdmissionLease envelope bytes.
func (s *SignerIdentity) SignLease(payload *apb.ZoneAdmissionLeasePayload) ([]byte, error) {
	payloadBytes, err := wire.MarshalZoneAdmissionLeasePayload(payload)
	if err != nil {
		return nil, err
	}
	return s.SignLeasePayloadBytes(payloadBytes)
}

// SignLeasePayloadBytes signs payloadBytes exactly as given and returns
// the canonical envelope bytes. Negative tests use it to sign payloads
// that a validating marshal would refuse.
func (s *SignerIdentity) SignLeasePayloadBytes(payloadBytes []byte) ([]byte, error) {
	signature, err := wire.SignZoneAdmissionLease(s.Key, payloadBytes)
	if err != nil {
		return nil, err
	}
	envelope := &apb.ZoneAdmissionLease{
		Contract:        apb.ZoneAdmissionLeaseContract,
		Payload:         payloadBytes,
		Signature:       signature,
		SignerKeyId:     s.KeyID,
		SignerCertChain: s.ChainDER,
	}
	return wire.MarshalZoneAdmissionLease(envelope)
}

func serial() *big.Int {
	value, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		panic(err)
	}
	return value
}
