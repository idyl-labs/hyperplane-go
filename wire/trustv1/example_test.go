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
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

// ExampleNewTrustSnapshot builds a snapshot holding one Ed25519 signing
// CA, validates it at an instant inside and outside its window, and parses
// it back from the canonical payload a consumer receives.
func ExampleNewTrustSnapshot() {
	issuedAt := time.Date(2030, 1, 2, 3, 0, 0, 0, time.UTC)

	// A trust generation is a public CA certificate; the snapshot never
	// carries its private key.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "example CA"},
		NotBefore:             issuedAt.Add(-time.Hour),
		NotAfter:              issuedAt.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		panic(err)
	}
	fingerprint := sha256.Sum256(der)

	snapshot, err := trustv1.NewTrustSnapshot("zone-a", trustv1.Purpose_PURPOSE_POD, 1,
		issuedAt, issuedAt.Add(time.Hour), []*trustv1.TrustGeneration{{
			GenerationId:      "gen-a",
			CertificateDer:    der,
			Sha256Fingerprint: fingerprint[:],
			NotBeforeUnixS:    template.NotBefore.Unix(),
			NotAfterUnixS:     template.NotAfter.Unix(),
			PublishedSequence: 1,
			State:             trustv1.GenerationState_GENERATION_STATE_ACTIVE,
		}})
	if err != nil {
		panic(err)
	}
	fmt.Println("zone:", snapshot.GetZone(), "sequence:", snapshot.GetSequence())
	fmt.Println("valid now:", trustv1.ValidateTrustSnapshotAt(snapshot, issuedAt.Add(time.Minute)) == nil)
	err = trustv1.ValidateTrustSnapshotAt(snapshot, issuedAt.Add(2*time.Hour))
	fmt.Println("expired later:", errors.Is(err, trustv1.ErrExpired))

	// A consumer receives the canonical payload and digest, and recovers
	// the same snapshot from them.
	received, err := trustv1.ParseCanonicalTrustSnapshotPayload(snapshot.GetCanonicalPayloadJson(), snapshot.GetSha256Digest())
	if err != nil {
		panic(err)
	}
	fmt.Println("parsed generation:", received.GetGenerations()[0].GetGenerationId())
	// Output:
	// zone: zone-a sequence: 1
	// valid now: true
	// expired later: true
	// parsed generation: gen-a
}

// ExampleJudgeSuccessor shows the install rule a consumer applies: the
// first snapshot installs, a re-delivery is a duplicate, and an older
// sequence is a rollback.
func ExampleJudgeSuccessor() {
	issuedAt := time.Date(2030, 1, 2, 3, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             issuedAt.Add(-time.Hour),
		NotAfter:              issuedAt.Add(30 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		panic(err)
	}
	fingerprint := sha256.Sum256(der)
	snapshotAt := func(sequence uint64) *trustv1.TrustSnapshot {
		snapshot, err := trustv1.NewTrustSnapshot("zone-a", trustv1.Purpose_PURPOSE_POD, sequence,
			issuedAt, issuedAt.Add(time.Hour), []*trustv1.TrustGeneration{{
				GenerationId:      "gen-a",
				CertificateDer:    der,
				Sha256Fingerprint: fingerprint[:],
				NotBeforeUnixS:    template.NotBefore.Unix(),
				NotAfterUnixS:     template.NotAfter.Unix(),
				PublishedSequence: 1,
				State:             trustv1.GenerationState_GENERATION_STATE_ACTIVE,
			}})
		if err != nil {
			panic(err)
		}
		return snapshot
	}

	var installed *trustv1.TrustSnapshot
	for _, next := range []*trustv1.TrustSnapshot{snapshotAt(2), snapshotAt(2), snapshotAt(1), snapshotAt(3)} {
		duplicate, err := trustv1.JudgeSuccessor(installed, next)
		switch {
		case errors.Is(err, trustv1.ErrRollback):
			fmt.Println("sequence", next.GetSequence(), "refused: rollback")
		case err != nil:
			fmt.Println("sequence", next.GetSequence(), "refused:", err)
		case duplicate:
			fmt.Println("sequence", next.GetSequence(), "already installed")
		default:
			installed = next
			fmt.Println("sequence", next.GetSequence(), "installed")
		}
	}
	// Output:
	// sequence 2 installed
	// sequence 2 already installed
	// sequence 1 refused: rollback
	// sequence 3 installed
}
