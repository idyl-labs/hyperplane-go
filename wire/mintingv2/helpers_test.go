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

package mintingv2_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	"github.com/idyl-labs/hyperplane-go/wire/mintingv2"
	"github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

// fixtureNow is the fixed instant every fixture is minted at.
var fixtureNow = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// fixtureCert is a certificate with the key that can issue beneath it.
type fixtureCert struct {
	der         []byte
	certificate *x509.Certificate
	key         ed25519.PrivateKey
}

// issue mints a certificate from template for a deterministic Ed25519 key
// derived from serial. A nil parent self-signs.
func issue(tb testing.TB, serial byte, template *x509.Certificate, parent *fixtureCert) fixtureCert {
	tb.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = serial
	key := ed25519.NewKeyFromSeed(seed)
	template.SerialNumber = big.NewInt(int64(serial) + 1)
	template.Subject = pkix.Name{CommonName: "minting fixture"}
	issuer, issuerKey := template, key
	if parent != nil {
		issuer, issuerKey = parent.certificate, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, key.Public(), issuerKey)
	if err != nil {
		tb.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return fixtureCert{der: der, certificate: certificate, key: key}
}

func newCA(tb testing.TB, serial byte, parent *fixtureCert) fixtureCert {
	tb.Helper()
	return issue(tb, serial, &x509.Certificate{
		NotBefore:             fixtureNow.Add(-24 * time.Hour),
		NotAfter:              fixtureNow.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, parent)
}

// newLeaf issues an SVID-shaped leaf under parent, valid for [notBefore, notAfter).
func newLeaf(tb testing.TB, parent *fixtureCert, notBefore, notAfter time.Time) fixtureCert {
	tb.Helper()
	return issue(tb, 200, &x509.Certificate{
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}, parent)
}

// snapshotFor seals a trust snapshot for purpose holding root, issued at
// fixtureNow and valid for one hour.
func snapshotFor(tb testing.TB, purpose trustv1.Purpose, root fixtureCert) *trustv1.TrustSnapshot {
	tb.Helper()
	fingerprint := sha256.Sum256(root.der)
	snapshot, err := trustv1.NewTrustSnapshot("zone-a", purpose, 1, fixtureNow, fixtureNow.Add(time.Hour), []*trustv1.TrustGeneration{{
		GenerationId:      "gen-a",
		CertificateDer:    root.der,
		Sha256Fingerprint: fingerprint[:],
		NotBeforeUnixS:    root.certificate.NotBefore.Unix(),
		NotAfterUnixS:     root.certificate.NotAfter.Unix(),
		PublishedSequence: 1,
		State:             trustv1.GenerationState_GENERATION_STATE_ACTIVE,
	}})
	if err != nil {
		tb.Fatal(err)
	}
	return snapshot
}

// mintFixture is a complete, valid mint: a POD trust snapshot, a leaf
// issued by its root, and the leaf's validity bounds.
type mintFixture struct {
	root      fixtureCert
	leaf      fixtureCert
	snapshot  *trustv1.TrustSnapshot
	lease     []byte
	notBefore uint64
	notAfter  uint64
}

func newMintFixture(tb testing.TB) mintFixture {
	tb.Helper()
	root := newCA(tb, 1, nil)
	leaf := newLeaf(tb, &root, fixtureNow.Add(-time.Minute), fixtureNow.Add(12*time.Hour))
	return mintFixture{
		root:      root,
		leaf:      leaf,
		snapshot:  snapshotFor(tb, trustv1.Purpose_PURPOSE_POD, root),
		lease:     bytes.Repeat([]byte{0x5a}, 512),
		notBefore: uint64(leaf.certificate.NotBefore.Unix()),
		notAfter:  uint64(leaf.certificate.NotAfter.Unix()),
	}
}

func (m mintFixture) podGeneration() *mintingv2.PodCredentialGeneration {
	return &mintingv2.PodCredentialGeneration{
		CertDer:       [][]byte{m.leaf.der},
		LeaseEnvelope: m.lease,
		RenewAtUnixS:  uint64(fixtureNow.Add(6 * time.Hour).Unix()),
		TrustSnapshot: m.snapshot,
	}
}

func (m mintFixture) sessionGeneration() *mintingv2.SessionCredentialGeneration {
	return &mintingv2.SessionCredentialGeneration{
		CertDer:       [][]byte{m.leaf.der},
		LeaseEnvelope: m.lease,
		TrustSnapshot: m.snapshot,
	}
}

// maxLease is a lease envelope of exactly the largest permitted size.
var maxLease = bytes.Repeat([]byte{0x5a}, admissionv3.MaxLeaseEnvelopeBytes)
