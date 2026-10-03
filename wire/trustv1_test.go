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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	trustpb "github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

var trustTestNow = time.Date(2026, 7, 21, 0, 0, 0, 0, time.UTC)

// TestTrustV1CanonicalCoreGolden pins the canonical JSON payload and its
// SHA-256 digest for a fixed trust snapshot. The digest identifies the
// snapshot and is what successor and equivocation checks compare, so
// changing either value is a wire-format change.
func TestTrustV1CanonicalCoreGolden(t *testing.T) {
	snapshot := &trustpb.TrustSnapshot{
		Zone:            "z1",
		Purpose:         trustpb.Purpose_PURPOSE_JOIN,
		Sequence:        7,
		IssuedAtUnixS:   trustTestNow.Unix(),
		ValidUntilUnixS: trustTestNow.Add(time.Hour).Unix(),
		Generations: []*trustpb.TrustGeneration{{
			GenerationId:      "g-1",
			CertificateDer:    []byte{1, 2, 3},
			Sha256Fingerprint: make([]byte, trustpb.SHA256Bytes),
			NotBeforeUnixS:    trustTestNow.Add(-24 * time.Hour).Unix(),
			NotAfterUnixS:     trustTestNow.Add(24 * time.Hour).Unix(),
			PublishedSequence: 6,
			State:             trustpb.GenerationState_GENERATION_STATE_ACTIVE,
		}},
	}
	payload, err := trustpb.CanonicalTrustSnapshotPayload(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"zone":"z1","purpose":"JOIN","sequence":7,"issuedAt":"2026-07-21T00:00:00Z","validUntil":"2026-07-21T01:00:00Z","generations":[{"generationId":"g-1","certificateDer":"AQID","sha256Fingerprint":"0000000000000000000000000000000000000000000000000000000000000000","notBefore":"2026-07-20T00:00:00Z","notAfter":"2026-07-22T00:00:00Z","publishedSequence":6,"state":"ACTIVE"}]}`
	if string(payload) != want {
		t.Fatalf("canonical payload:\n%s\nwant:\n%s", payload, want)
	}
	digest := sha256.Sum256(payload)
	if got := hex.EncodeToString(digest[:]); got != "5912fff35d3d64e2fb04fd241847d3309d6798ebf2cc39cc238ea127356de8b9" {
		t.Fatalf("canonical digest = %s", got)
	}
}

func TestTrustV1ValidationAndMonotonicInstall(t *testing.T) {
	snapshot, _, _ := testPodTrustPair(t)
	if err := trustpb.ValidateTrustSnapshotAt(snapshot, trustTestNow); err != nil {
		t.Fatalf("honest snapshot refused: %v", err)
	}
	parsed, err := trustpb.ParseCanonicalTrustSnapshotPayload(snapshot.GetCanonicalPayloadJson(), snapshot.GetSha256Digest())
	if err != nil {
		t.Fatalf("canonical parse refused: %v", err)
	}
	if !proto.Equal(parsed, snapshot) {
		t.Fatal("canonical parse did not reconstruct structured snapshot")
	}
	if duplicate, err := trustpb.JudgeSuccessor(snapshot, proto.Clone(snapshot).(*trustpb.TrustSnapshot)); err != nil || !duplicate {
		t.Fatalf("exact duplicate judgment = duplicate %v, err %v", duplicate, err)
	}
	next, err := trustpb.NewTrustSnapshot(snapshot.GetZone(), snapshot.GetPurpose(), 2, trustTestNow.Add(time.Minute), trustTestNow.Add(time.Hour), snapshot.GetGenerations())
	if err != nil {
		t.Fatal(err)
	}
	if duplicate, err := trustpb.JudgeSuccessor(snapshot, next); err != nil || duplicate {
		t.Fatalf("advance judgment = duplicate %v, err %v", duplicate, err)
	}
	if _, err := trustpb.JudgeSuccessor(next, snapshot); err == nil {
		t.Fatal("sequence rollback must refuse")
	}
	equivocated := proto.Clone(snapshot).(*trustpb.TrustSnapshot)
	equivocated.Sha256Digest[0] ^= 0xff
	if _, err := trustpb.JudgeSuccessor(snapshot, equivocated); err == nil {
		t.Fatal("same-sequence digest equivocation must refuse")
	}
}

func TestTrustV1RefusalMatrix(t *testing.T) {
	base, _, _ := testPodTrustPair(t)
	for _, row := range []struct {
		name string
		mut  func(*trustpb.TrustSnapshot)
	}{
		{"empty", func(s *trustpb.TrustSnapshot) { s.Generations = nil }},
		{"wrong digest", func(s *trustpb.TrustSnapshot) { s.Sha256Digest[0] ^= 1 }},
		{"wrong purpose encoding", func(s *trustpb.TrustSnapshot) { s.Purpose = trustpb.Purpose_PURPOSE_UNSPECIFIED }},
		{"unsorted IDs", func(s *trustpb.TrustSnapshot) {
			second := proto.Clone(s.Generations[0]).(*trustpb.TrustGeneration)
			second.GenerationId = "a-before"
			s.Generations = append(s.Generations, second)
		}},
		{"retired root", func(s *trustpb.TrustSnapshot) {
			s.Generations[0].State = trustpb.GenerationState_GENERATION_STATE_RETIRED
		}},
		{"key bearing bytes", func(s *trustpb.TrustSnapshot) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			s.Generations[0].CertificateDer, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown fields", func(s *trustpb.TrustSnapshot) { s.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) }},
	} {
		t.Run(row.name, func(t *testing.T) {
			got := proto.Clone(base).(*trustpb.TrustSnapshot)
			row.mut(got)
			if err := trustpb.ValidateTrustSnapshot(got); err == nil {
				t.Fatal("hostile snapshot accepted")
			}
		})
	}
	if err := trustpb.ValidateTrustSnapshotAt(base, trustTestNow.Add(2*time.Hour)); err == nil {
		t.Fatal("expired snapshot must refuse")
	}
}

// testPodTrustPair builds a pod-purpose trust snapshot holding one fresh
// root, and returns it with a leaf certificate (DER) issued by that root
// and the parsed root certificate.
func testPodTrustPair(t *testing.T) (*trustpb.TrustSnapshot, []byte, *x509.Certificate) {
	t.Helper()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{},
		NotBefore:             trustTestNow.Add(-time.Hour),
		NotAfter:              trustTestNow.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{},
		NotBefore:             trustTestNow.Add(-time.Minute),
		NotAfter:              trustTestNow.Add(12 * time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, leafPublic, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(rootDER)
	snapshot, err := trustpb.NewTrustSnapshot("z1", trustpb.Purpose_PURPOSE_POD, 1, trustTestNow, trustTestNow.Add(time.Hour), []*trustpb.TrustGeneration{{
		GenerationId:      "pod-generation-1",
		CertificateDer:    rootDER,
		Sha256Fingerprint: fingerprint[:],
		NotBeforeUnixS:    root.NotBefore.Unix(),
		NotAfterUnixS:     root.NotAfter.Unix(),
		PublishedSequence: 1,
		State:             trustpb.GenerationState_GENERATION_STATE_ACTIVE,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot, leafDER, root
}

func TestTrustV1CanonicalPayloadCopyIsIndependent(t *testing.T) {
	snapshot, _, _ := testPodTrustPair(t)
	payload := append([]byte(nil), snapshot.GetCanonicalPayloadJson()...)
	parsed, err := trustpb.ParseCanonicalTrustSnapshotPayload(payload, snapshot.GetSha256Digest())
	if err != nil {
		t.Fatal(err)
	}
	parsed.CanonicalPayloadJson[0] ^= 1
	if !bytes.Equal(payload, snapshot.GetCanonicalPayloadJson()) {
		t.Fatal("parsed snapshot aliases caller payload")
	}
}
