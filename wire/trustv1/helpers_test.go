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

package trustv1_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

// fixtureNow is the fixed instant every fixture is minted at, so results
// never depend on the wall clock.
var fixtureNow = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

// fixtureCA is one Ed25519 signing CA certificate.
type fixtureCA struct {
	der         []byte
	certificate *x509.Certificate
}

// newFixtureCA mints an Ed25519 signing CA whose key derives from serial,
// so repeated calls with the same arguments produce the same certificate.
func newFixtureCA(tb testing.TB, serial byte, notBefore, notAfter time.Time) fixtureCA {
	tb.Helper()
	return newFixtureCertificate(tb, serial, &x509.Certificate{
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	})
}

// newFixtureCertificate self-signs template with a deterministic Ed25519
// key derived from serial.
func newFixtureCertificate(tb testing.TB, serial byte, template *x509.Certificate) fixtureCA {
	tb.Helper()
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = serial
	key := ed25519.NewKeyFromSeed(seed)
	template.SerialNumber = big.NewInt(int64(serial) + 1)
	template.Subject = pkix.Name{CommonName: "trust fixture CA"}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		tb.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return fixtureCA{der: der, certificate: certificate}
}

// defaultCA is valid from a day before fixtureNow for three days.
func defaultCA(tb testing.TB, serial byte) fixtureCA {
	tb.Helper()
	return newFixtureCA(tb, serial, fixtureNow.Add(-24*time.Hour), fixtureNow.Add(72*time.Hour))
}

// generationFor describes ca as an ACTIVE generation published at
// sequence 1, with validity and fingerprint taken from the certificate.
func generationFor(ca fixtureCA, id string) *trustv1.TrustGeneration {
	fingerprint := sha256.Sum256(ca.der)
	return &trustv1.TrustGeneration{
		GenerationId:      id,
		CertificateDer:    append([]byte(nil), ca.der...),
		Sha256Fingerprint: fingerprint[:],
		NotBeforeUnixS:    ca.certificate.NotBefore.Unix(),
		NotAfterUnixS:     ca.certificate.NotAfter.Unix(),
		PublishedSequence: 1,
		State:             trustv1.GenerationState_GENERATION_STATE_ACTIVE,
	}
}

// validSnapshot returns a POD snapshot for zone-a at sequence 1, issued at
// fixtureNow and valid for one hour, holding one ACTIVE generation.
func validSnapshot(tb testing.TB) *trustv1.TrustSnapshot {
	tb.Helper()
	snapshot, err := trustv1.NewTrustSnapshot("zone-a", trustv1.Purpose_PURPOSE_POD, 1,
		fixtureNow, fixtureNow.Add(time.Hour), []*trustv1.TrustGeneration{generationFor(defaultCA(tb, 1), "gen-a")})
	if err != nil {
		tb.Fatal(err)
	}
	return snapshot
}

// reseal recomputes the canonical payload and digest of a mutated
// snapshot, so a refusal can only come from the structured field the test
// changed. A snapshot whose payload cannot be built is left unchanged.
func reseal(snapshot *trustv1.TrustSnapshot) {
	payload, err := trustv1.CanonicalTrustSnapshotPayload(snapshot)
	if err != nil {
		return
	}
	digest := sha256.Sum256(payload)
	snapshot.CanonicalPayloadJson = payload
	snapshot.Sha256Digest = digest[:]
}

func cloneSnapshot(snapshot *trustv1.TrustSnapshot) *trustv1.TrustSnapshot {
	return proto.Clone(snapshot).(*trustv1.TrustSnapshot)
}
