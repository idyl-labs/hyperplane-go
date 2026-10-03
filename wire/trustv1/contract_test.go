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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

// TestNewTrustSnapshotSortsAndSeals checks that the constructor sorts
// generations by ID, records the canonical payload and its SHA-256 digest,
// and returns a snapshot that validates. The digest is the snapshot's
// identity for successor judgments, so it must be over the exact payload.
func TestNewTrustSnapshotSortsAndSeals(t *testing.T) {
	inputs := []*trustv1.TrustGeneration{
		generationFor(defaultCA(t, 3), "gen-c"),
		generationFor(defaultCA(t, 1), "gen-a"),
		generationFor(defaultCA(t, 2), "gen-b"),
	}
	snapshot, err := trustv1.NewTrustSnapshot("zone-a", trustv1.Purpose_PURPOSE_JOIN, 4,
		fixtureNow, fixtureNow.Add(time.Hour), inputs)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, generation := range snapshot.GetGenerations() {
		ids = append(ids, generation.GetGenerationId())
	}
	if strings.Join(ids, ",") != "gen-a,gen-b,gen-c" {
		t.Fatalf("generation order = %v", ids)
	}
	payload, err := trustv1.CanonicalTrustSnapshotPayload(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, snapshot.GetCanonicalPayloadJson()) {
		t.Fatal("recorded payload is not the canonical payload")
	}
	digest := sha256.Sum256(payload)
	if !bytes.Equal(digest[:], snapshot.GetSha256Digest()) {
		t.Fatal("recorded digest is not SHA-256 of the payload")
	}
	if err := trustv1.ValidateTrustSnapshot(snapshot); err != nil {
		t.Fatalf("constructed snapshot does not validate: %v", err)
	}
}

// TestNewTrustSnapshotDoesNotAliasInputs checks that the constructor
// copies the caller's generations: neither the caller's slice order nor a
// later change to a caller's generation can alter the sealed snapshot.
func TestNewTrustSnapshotDoesNotAliasInputs(t *testing.T) {
	inputs := []*trustv1.TrustGeneration{
		generationFor(defaultCA(t, 2), "gen-b"),
		generationFor(defaultCA(t, 1), "gen-a"),
	}
	snapshot, err := trustv1.NewTrustSnapshot("zone-a", trustv1.Purpose_PURPOSE_POD, 1,
		fixtureNow, fixtureNow.Add(time.Hour), inputs)
	if err != nil {
		t.Fatal(err)
	}
	if inputs[0].GetGenerationId() != "gen-b" {
		t.Fatal("constructor reordered the caller's slice")
	}
	inputs[1].GenerationId = "changed"
	inputs[1].CertificateDer[0] ^= 0xff
	if err := trustv1.ValidateTrustSnapshot(snapshot); err != nil {
		t.Fatalf("caller mutation reached the sealed snapshot: %v", err)
	}
	if snapshot.GetGenerations()[0].GetGenerationId() != "gen-a" {
		t.Fatal("caller mutation reached the sealed snapshot")
	}
}

// TestNewTrustSnapshotNormalizesTimesToUnixSeconds checks that issue and
// expiry instants are recorded as whole UTC seconds whatever the caller's
// location, so the canonical payload never depends on local time zones.
func TestNewTrustSnapshotNormalizesTimesToUnixSeconds(t *testing.T) {
	east := time.FixedZone("east", 5*3600)
	issued := fixtureNow.In(east).Add(400 * time.Millisecond)
	snapshot, err := trustv1.NewTrustSnapshot("zone-a", trustv1.Purpose_PURPOSE_POD, 1,
		issued, issued.Add(time.Hour), []*trustv1.TrustGeneration{generationFor(defaultCA(t, 1), "gen-a")})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.GetIssuedAtUnixS() != fixtureNow.Unix() || snapshot.GetValidUntilUnixS() != fixtureNow.Add(time.Hour).Unix() {
		t.Fatalf("times = %d..%d", snapshot.GetIssuedAtUnixS(), snapshot.GetValidUntilUnixS())
	}
	if !bytes.Contains(snapshot.GetCanonicalPayloadJson(), []byte(`"issuedAt":"2030-01-02T03:04:05Z"`)) {
		t.Fatalf("payload does not carry the UTC issue instant: %s", snapshot.GetCanonicalPayloadJson())
	}
}

// TestNewTrustSnapshotRefusesInvalidInput checks that the constructor never
// returns a snapshot that would fail validation, and that every refusal is
// ErrMalformed.
func TestNewTrustSnapshotRefusesInvalidInput(t *testing.T) {
	good := []*trustv1.TrustGeneration{generationFor(defaultCA(t, 1), "gen-a")}
	for _, row := range []struct {
		name        string
		zone        string
		purpose     trustv1.Purpose
		sequence    uint64
		generations []*trustv1.TrustGeneration
	}{
		{"unspecified purpose", "zone-a", trustv1.Purpose_PURPOSE_UNSPECIFIED, 1, good},
		{"nil generation", "zone-a", trustv1.Purpose_PURPOSE_POD, 1, []*trustv1.TrustGeneration{nil}},
		{"zero sequence", "zone-a", trustv1.Purpose_PURPOSE_POD, 0, good},
		{"invalid zone", "Zone-A", trustv1.Purpose_PURPOSE_POD, 1, good},
		{"no generations", "zone-a", trustv1.Purpose_PURPOSE_POD, 1, nil},
	} {
		t.Run(row.name, func(t *testing.T) {
			snapshot, err := trustv1.NewTrustSnapshot(row.zone, row.purpose, row.sequence,
				fixtureNow, fixtureNow.Add(time.Hour), row.generations)
			if !errors.Is(err, trustv1.ErrMalformed) || snapshot != nil {
				t.Fatalf("got snapshot %v, err %v; want nil and ErrMalformed", snapshot != nil, err)
			}
		})
	}
}

// TestCanonicalTrustSnapshotPayloadShape pins the JSON field names, field
// order, and encodings of the canonical payload: RFC 3339 UTC instants,
// base64 DER, lowercase hex fingerprints, and text enums. The digest is
// computed over these bytes, so any change to them is a wire change.
func TestCanonicalTrustSnapshotPayloadShape(t *testing.T) {
	snapshot := &trustv1.TrustSnapshot{
		Zone:            "zone-a",
		Purpose:         trustv1.Purpose_PURPOSE_POD,
		Sequence:        9,
		IssuedAtUnixS:   fixtureNow.Unix(),
		ValidUntilUnixS: fixtureNow.Add(time.Hour).Unix(),
		Generations: []*trustv1.TrustGeneration{{
			GenerationId:      "gen-a",
			CertificateDer:    []byte{0xfb, 0xff},
			Sha256Fingerprint: []byte{0xab, 0xcd},
			NotBeforeUnixS:    fixtureNow.Add(-time.Hour).Unix(),
			NotAfterUnixS:     fixtureNow.Add(2 * time.Hour).Unix(),
			PublishedSequence: 8,
			State:             trustv1.GenerationState_GENERATION_STATE_RETIRING,
		}},
	}
	payload, err := trustv1.CanonicalTrustSnapshotPayload(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"zone":"zone-a","purpose":"POD","sequence":9,"issuedAt":"2030-01-02T03:04:05Z","validUntil":"2030-01-02T04:04:05Z",` +
		`"generations":[{"generationId":"gen-a","certificateDer":"+/8=","sha256Fingerprint":"abcd",` +
		`"notBefore":"2030-01-02T02:04:05Z","notAfter":"2030-01-02T05:04:05Z","publishedSequence":8,"state":"RETIRING"}]}`
	if string(payload) != want {
		t.Fatalf("payload:\n%s\nwant:\n%s", payload, want)
	}
	again, err := trustv1.CanonicalTrustSnapshotPayload(cloneSnapshot(snapshot))
	if err != nil || !bytes.Equal(again, payload) {
		t.Fatal("canonical payload is not deterministic")
	}
}

// TestCanonicalTrustSnapshotPayloadEncodesEveryState checks that every
// generation state has a text form, including the non-distributable ones:
// the payload builder does not validate, so a producer can describe any
// state, and only the validators decide what is installable.
func TestCanonicalTrustSnapshotPayloadEncodesEveryState(t *testing.T) {
	for state, text := range map[trustv1.GenerationState]string{
		trustv1.GenerationState_GENERATION_STATE_PUBLISHING: "PUBLISHING",
		trustv1.GenerationState_GENERATION_STATE_ACTIVE:     "ACTIVE",
		trustv1.GenerationState_GENERATION_STATE_RETIRING:   "RETIRING",
		trustv1.GenerationState_GENERATION_STATE_RETIRED:    "RETIRED",
		trustv1.GenerationState_GENERATION_STATE_REVOKED:    "REVOKED",
	} {
		snapshot := &trustv1.TrustSnapshot{
			Purpose:     trustv1.Purpose_PURPOSE_JOIN,
			Generations: []*trustv1.TrustGeneration{{State: state}},
		}
		payload, err := trustv1.CanonicalTrustSnapshotPayload(snapshot)
		if err != nil {
			t.Fatalf("%s: %v", state, err)
		}
		if !bytes.Contains(payload, []byte(`"state":"`+text+`"`)) || !bytes.Contains(payload, []byte(`"purpose":"JOIN"`)) {
			t.Fatalf("%s: payload %s", state, payload)
		}
	}
}

// TestCanonicalTrustSnapshotPayloadRefusesUnencodable checks the cases the
// payload builder cannot represent: an absent snapshot, a purpose or state
// with no text form, and a nil generation. Each is ErrMalformed.
func TestCanonicalTrustSnapshotPayloadRefusesUnencodable(t *testing.T) {
	for _, row := range []struct {
		name     string
		snapshot *trustv1.TrustSnapshot
	}{
		{"absent", nil},
		{"unspecified purpose", &trustv1.TrustSnapshot{}},
		{"unknown purpose", &trustv1.TrustSnapshot{Purpose: trustv1.Purpose(99)}},
		{"nil generation", &trustv1.TrustSnapshot{Purpose: trustv1.Purpose_PURPOSE_POD, Generations: []*trustv1.TrustGeneration{nil}}},
		{"unspecified state", &trustv1.TrustSnapshot{Purpose: trustv1.Purpose_PURPOSE_POD, Generations: []*trustv1.TrustGeneration{{}}}},
		{"unknown state", &trustv1.TrustSnapshot{Purpose: trustv1.Purpose_PURPOSE_POD, Generations: []*trustv1.TrustGeneration{{State: trustv1.GenerationState(42)}}}},
	} {
		t.Run(row.name, func(t *testing.T) {
			payload, err := trustv1.CanonicalTrustSnapshotPayload(row.snapshot)
			if !errors.Is(err, trustv1.ErrMalformed) || payload != nil {
				t.Fatalf("payload %q, err %v; want nil and ErrMalformed", payload, err)
			}
		})
	}
}

// TestParseCanonicalTrustSnapshotPayloadRoundTrip checks that parsing a
// sealed snapshot's payload reconstructs exactly the structured snapshot,
// for every distributable state, and that the result owns its bytes
// rather than aliasing the caller's.
func TestParseCanonicalTrustSnapshotPayloadRoundTrip(t *testing.T) {
	publishing := generationFor(defaultCA(t, 1), "gen-a")
	publishing.State = trustv1.GenerationState_GENERATION_STATE_PUBLISHING
	retiring := generationFor(defaultCA(t, 3), "gen-c")
	retiring.State = trustv1.GenerationState_GENERATION_STATE_RETIRING
	snapshot, err := trustv1.NewTrustSnapshot("zone-a", trustv1.Purpose_PURPOSE_JOIN, 3,
		fixtureNow, fixtureNow.Add(time.Hour), []*trustv1.TrustGeneration{
			publishing,
			generationFor(defaultCA(t, 2), "gen-b"),
			retiring,
		})
	if err != nil {
		t.Fatal(err)
	}
	payload := append([]byte(nil), snapshot.GetCanonicalPayloadJson()...)
	digest := append([]byte(nil), snapshot.GetSha256Digest()...)
	parsed, err := trustv1.ParseCanonicalTrustSnapshotPayload(payload, digest)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(parsed, snapshot) {
		t.Fatal("parse did not reconstruct the structured snapshot")
	}
	parsed.CanonicalPayloadJson[0] ^= 0xff
	parsed.Sha256Digest[0] ^= 0xff
	if !bytes.Equal(payload, snapshot.GetCanonicalPayloadJson()) || !bytes.Equal(digest, snapshot.GetSha256Digest()) {
		t.Fatal("parsed snapshot aliases the caller's payload or digest")
	}
}

// TestParseCanonicalTrustSnapshotPayloadRefusals covers every way a payload
// can fail the strict parse: size bounds, JSON that is not exactly one
// object, unknown fields, unknown enum text, bad hex, any encoding that is
// not byte-identical to the canonical form, and a digest or content that
// fails validation. Every refusal is ErrMalformed.
func TestParseCanonicalTrustSnapshotPayloadRefusals(t *testing.T) {
	snapshot := validSnapshot(t)
	payload := snapshot.GetCanonicalPayloadJson()
	digest := snapshot.GetSha256Digest()
	digestOf := func(b []byte) []byte {
		sum := sha256.Sum256(b)
		return sum[:]
	}
	replace := func(old, replacement string) []byte {
		if !bytes.Contains(payload, []byte(old)) {
			t.Fatalf("payload does not contain %q", old)
		}
		return bytes.Replace(payload, []byte(old), []byte(replacement), 1)
	}
	retired := cloneSnapshot(snapshot)
	retired.Generations[0].State = trustv1.GenerationState_GENERATION_STATE_RETIRED
	retiredPayload, err := trustv1.CanonicalTrustSnapshotPayload(retired)
	if err != nil {
		t.Fatal(err)
	}
	revoked := cloneSnapshot(snapshot)
	revoked.Generations[0].State = trustv1.GenerationState_GENERATION_STATE_REVOKED
	revokedPayload, err := trustv1.CanonicalTrustSnapshotPayload(revoked)
	if err != nil {
		t.Fatal(err)
	}
	var reordered map[string]any
	if err := json.Unmarshal(payload, &reordered); err != nil {
		t.Fatal(err)
	}
	sortedKeys, err := json.Marshal(reordered)
	if err != nil {
		t.Fatal(err)
	}
	oversize := bytes.Repeat([]byte{' '}, trustv1.MaxCanonicalPayloadJSONBytes+1)
	fingerprintHex := hex.EncodeToString(snapshot.GetGenerations()[0].GetSha256Fingerprint())

	for _, row := range []struct {
		name    string
		payload []byte
		digest  []byte
	}{
		{"empty payload", nil, digest},
		{"oversize payload", oversize, digestOf(oversize)},
		{"absent digest", payload, nil},
		{"short digest", payload, digest[:trustv1.SHA256Bytes-1]},
		{"long digest", payload, append(append([]byte(nil), digest...), 0)},
		{"not JSON", []byte("not json"), digestOf([]byte("not json"))},
		{"JSON array", []byte("[]"), digestOf([]byte("[]"))},
		{"unknown field", replace(`{"zone"`, `{"extra":1,"zone"`), digest},
		{"trailing value", append(append([]byte(nil), payload...), "{}"...), digest},
		{"trailing garbage", append(append([]byte(nil), payload...), 'x'), digest},
		{"trailing whitespace", append(append([]byte(nil), payload...), ' '), digest},
		{"lowercase purpose", replace(`"POD"`, `"pod"`), digest},
		{"unknown purpose", replace(`"POD"`, `"UNSPECIFIED"`), digest},
		{"lowercase state", replace(`"ACTIVE"`, `"active"`), digest},
		{"non-hex fingerprint", replace(`"sha256Fingerprint":"`, `"sha256Fingerprint":"zz`), digest},
		{"uppercase fingerprint", replace(fingerprintHex, strings.ToUpper(fingerprintHex)), digest},
		{"reordered keys", sortedKeys, digestOf(sortedKeys)},
		{"offset timestamp", replace(`"issuedAt":"2030-01-02T03:04:05Z"`, `"issuedAt":"2030-01-02T04:04:05+01:00"`), digest},
		{"digest of other bytes", payload, digestOf([]byte("other"))},
		{"retired generation", retiredPayload, digestOf(retiredPayload)},
		{"revoked generation", revokedPayload, digestOf(revokedPayload)},
	} {
		t.Run(row.name, func(t *testing.T) {
			parsed, err := trustv1.ParseCanonicalTrustSnapshotPayload(row.payload, row.digest)
			if !errors.Is(err, trustv1.ErrMalformed) || parsed != nil {
				t.Fatalf("parsed %v, err %v; want nil and ErrMalformed", parsed != nil, err)
			}
		})
	}
}

// TestValidateTrustSnapshotAcceptsBoundaries checks the inclusive limits a
// producer may rely on: the longest zone and generation ID, the longest
// snapshot validity, the full generation count, every distributable state,
// and a generation published at the snapshot's own sequence.
func TestValidateTrustSnapshotAcceptsBoundaries(t *testing.T) {
	longest := strings.Repeat("z", trustv1.MaxZoneBytes)
	generations := make([]*trustv1.TrustGeneration, 0, trustv1.MaxGenerations)
	states := []trustv1.GenerationState{
		trustv1.GenerationState_GENERATION_STATE_PUBLISHING,
		trustv1.GenerationState_GENERATION_STATE_ACTIVE,
		trustv1.GenerationState_GENERATION_STATE_RETIRING,
	}
	for i := range trustv1.MaxGenerations {
		generation := generationFor(defaultCA(t, byte(i+1)), fmt.Sprintf("gen-%02d", i))
		generation.State = states[i%len(states)]
		generation.PublishedSequence = 5
		generations = append(generations, generation)
	}
	generations[0].GenerationId = "0" + strings.Repeat("g", trustv1.MaxGenerationIDBytes-1)
	snapshot, err := trustv1.NewTrustSnapshot(longest, trustv1.Purpose_PURPOSE_JOIN, 5,
		fixtureNow, fixtureNow.Add(trustv1.MaxSnapshotValidity), generations)
	if err != nil {
		t.Fatalf("boundary snapshot refused: %v", err)
	}
	if len(snapshot.GetGenerations()) != trustv1.MaxGenerations {
		t.Fatalf("generation count = %d", len(snapshot.GetGenerations()))
	}
}

// TestValidateTrustSnapshotRefusalMatrix mutates one fact of a valid
// snapshot at a time, re-sealing the payload and digest so the refusal can
// only come from the mutated fact. Every refusal must be ErrMalformed, the
// one error class a consumer needs to discard a snapshot.
func TestValidateTrustSnapshotRefusalMatrix(t *testing.T) {
	base := validSnapshot(t)
	other := defaultCA(t, 2)
	ecdsaCA := ecdsaFixtureCA(t)
	nonCA := newFixtureCertificate(t, 3, &x509.Certificate{
		NotBefore: fixtureNow.Add(-time.Hour), NotAfter: fixtureNow.Add(72 * time.Hour),
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	})
	noCertSign := newFixtureCertificate(t, 4, &x509.Certificate{
		NotBefore: fixtureNow.Add(-time.Hour), NotAfter: fixtureNow.Add(72 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
	})
	shortLived := newFixtureCA(t, 5, fixtureNow.Add(-time.Hour), fixtureNow.Add(30*time.Minute))
	setGeneration := func(ca fixtureCA) func(*trustv1.TrustSnapshot) {
		return func(s *trustv1.TrustSnapshot) { s.Generations[0] = generationFor(ca, "gen-a") }
	}

	for _, row := range []struct {
		name   string
		mutate func(*trustv1.TrustSnapshot)
		raw    bool // skip re-sealing: the mutation targets the payload or digest itself
	}{
		{name: "snapshot unknown field", mutate: func(s *trustv1.TrustSnapshot) { s.ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01}) }},
		{name: "generation unknown field", mutate: func(s *trustv1.TrustSnapshot) {
			s.Generations[0].ProtoReflect().SetUnknown([]byte{0xa0, 0x06, 0x01})
		}},
		{name: "empty zone", mutate: func(s *trustv1.TrustSnapshot) { s.Zone = "" }},
		{name: "uppercase zone", mutate: func(s *trustv1.TrustSnapshot) { s.Zone = "Zone-a" }},
		{name: "zone with leading hyphen", mutate: func(s *trustv1.TrustSnapshot) { s.Zone = "-zone" }},
		{name: "zone with trailing hyphen", mutate: func(s *trustv1.TrustSnapshot) { s.Zone = "zone-" }},
		{name: "zone with dot", mutate: func(s *trustv1.TrustSnapshot) { s.Zone = "zone.a" }},
		{name: "zone one byte over", mutate: func(s *trustv1.TrustSnapshot) { s.Zone = strings.Repeat("z", trustv1.MaxZoneBytes+1) }},
		{name: "zero sequence", mutate: func(s *trustv1.TrustSnapshot) { s.Sequence = 0 }},
		{name: "unspecified purpose", mutate: func(s *trustv1.TrustSnapshot) { s.Purpose = trustv1.Purpose_PURPOSE_UNSPECIFIED }},
		{name: "unknown purpose", mutate: func(s *trustv1.TrustSnapshot) { s.Purpose = trustv1.Purpose(7) }},
		{name: "zero issued at", mutate: func(s *trustv1.TrustSnapshot) { s.IssuedAtUnixS = 0 }},
		{name: "negative issued at", mutate: func(s *trustv1.TrustSnapshot) { s.IssuedAtUnixS = -1 }},
		{name: "empty validity", mutate: func(s *trustv1.TrustSnapshot) { s.ValidUntilUnixS = s.IssuedAtUnixS }},
		{name: "inverted validity", mutate: func(s *trustv1.TrustSnapshot) { s.ValidUntilUnixS = s.IssuedAtUnixS - 1 }},
		{name: "validity one second over", mutate: func(s *trustv1.TrustSnapshot) {
			s.ValidUntilUnixS = s.IssuedAtUnixS + int64(trustv1.MaxSnapshotValidity/time.Second) + 1
		}},
		{name: "no generations", mutate: func(s *trustv1.TrustSnapshot) { s.Generations = nil }},
		{name: "one generation over", mutate: func(s *trustv1.TrustSnapshot) {
			s.Generations = nil
			for i := range trustv1.MaxGenerations + 1 {
				s.Generations = append(s.Generations, &trustv1.TrustGeneration{
					GenerationId: fmt.Sprintf("gen-%02d", i), State: trustv1.GenerationState_GENERATION_STATE_ACTIVE,
				})
			}
		}},
		{name: "nil generation", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0] = nil }},
		{name: "empty generation ID", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].GenerationId = "" }},
		{name: "generation ID with space", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].GenerationId = "gen a" }},
		{name: "generation ID with DEL", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].GenerationId = "gen\x7f" }},
		{name: "generation ID not UTF-8", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].GenerationId = "gen\xff" }},
		{name: "generation ID one byte over", mutate: func(s *trustv1.TrustSnapshot) {
			s.Generations[0].GenerationId = strings.Repeat("g", trustv1.MaxGenerationIDBytes+1)
		}},
		{name: "unsorted generation IDs", mutate: func(s *trustv1.TrustSnapshot) {
			s.Generations = append(s.Generations, generationFor(other, "gen-0"))
		}},
		{name: "duplicate generation IDs", mutate: func(s *trustv1.TrustSnapshot) {
			s.Generations = append(s.Generations, generationFor(other, "gen-a"))
		}},
		{name: "duplicate certificate", mutate: func(s *trustv1.TrustSnapshot) {
			duplicate := proto.Clone(s.Generations[0]).(*trustv1.TrustGeneration)
			duplicate.GenerationId = "gen-b"
			s.Generations = append(s.Generations, duplicate)
		}},
		{name: "empty certificate", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].CertificateDer = nil }},
		{name: "certificate one byte over", mutate: func(s *trustv1.TrustSnapshot) {
			s.Generations[0].CertificateDer = make([]byte, trustv1.MaxCertificateDERBytes+1)
		}},
		{name: "certificate not DER", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].CertificateDer = []byte{0x30, 0x00} }},
		{name: "ECDSA CA", mutate: setGeneration(ecdsaCA)},
		{name: "Ed25519 non-CA", mutate: setGeneration(nonCA)},
		{name: "CA without certSign", mutate: setGeneration(noCertSign)},
		{name: "advertised not_before differs", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].NotBeforeUnixS-- }},
		{name: "advertised not_after differs", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].NotAfterUnixS++ }},
		{name: "snapshot outlives generation", mutate: setGeneration(shortLived)},
		{name: "fingerprint differs", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].Sha256Fingerprint[0] ^= 1 }},
		{name: "fingerprint absent", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].Sha256Fingerprint = nil }},
		{name: "published sequence zero", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].PublishedSequence = 0 }},
		{name: "published after snapshot", mutate: func(s *trustv1.TrustSnapshot) { s.Generations[0].PublishedSequence = s.Sequence + 1 }},
		{name: "retired generation", mutate: func(s *trustv1.TrustSnapshot) {
			s.Generations[0].State = trustv1.GenerationState_GENERATION_STATE_RETIRED
		}},
		{name: "revoked generation", mutate: func(s *trustv1.TrustSnapshot) {
			s.Generations[0].State = trustv1.GenerationState_GENERATION_STATE_REVOKED
		}},
		{name: "unspecified state", mutate: func(s *trustv1.TrustSnapshot) {
			s.Generations[0].State = trustv1.GenerationState_GENERATION_STATE_UNSPECIFIED
		}},
		{name: "payload absent", raw: true, mutate: func(s *trustv1.TrustSnapshot) { s.CanonicalPayloadJson = nil }},
		{name: "payload one byte over", raw: true, mutate: func(s *trustv1.TrustSnapshot) {
			s.CanonicalPayloadJson = make([]byte, trustv1.MaxCanonicalPayloadJSONBytes+1)
		}},
		{name: "digest short", raw: true, mutate: func(s *trustv1.TrustSnapshot) { s.Sha256Digest = s.Sha256Digest[:trustv1.SHA256Bytes-1] }},
		{name: "payload disagrees with fields", raw: true, mutate: func(s *trustv1.TrustSnapshot) {
			s.CanonicalPayloadJson = append(s.CanonicalPayloadJson, ' ')
			digest := sha256.Sum256(s.CanonicalPayloadJson)
			s.Sha256Digest = digest[:]
		}},
		{name: "fields disagree with payload", raw: true, mutate: func(s *trustv1.TrustSnapshot) { s.Sequence = 2 }},
		{name: "digest differs", raw: true, mutate: func(s *trustv1.TrustSnapshot) { s.Sha256Digest[0] ^= 1 }},
	} {
		t.Run(row.name, func(t *testing.T) {
			snapshot := cloneSnapshot(base)
			row.mutate(snapshot)
			if !row.raw {
				reseal(snapshot)
			}
			if err := trustv1.ValidateTrustSnapshot(snapshot); !errors.Is(err, trustv1.ErrMalformed) {
				t.Fatalf("err = %v, want ErrMalformed", err)
			}
		})
	}
	if err := trustv1.ValidateTrustSnapshot(nil); !errors.Is(err, trustv1.ErrMalformed) {
		t.Fatalf("nil snapshot: err = %v, want ErrMalformed", err)
	}
	if err := trustv1.ValidateTrustSnapshot(base); err != nil {
		t.Fatalf("matrix mutated the base snapshot: %v", err)
	}
}

// TestValidateTrustSnapshotAtWindow checks the half-open validity window
// [issued_at, valid_until): accepted from the issue instant up to, but not
// including, the expiry instant, and ErrExpired outside it. ErrExpired is
// distinct from ErrMalformed, so a consumer can tell a stale snapshot from
// a corrupt one.
func TestValidateTrustSnapshotAtWindow(t *testing.T) {
	snapshot := validSnapshot(t)
	issued := time.Unix(snapshot.GetIssuedAtUnixS(), 0)
	until := time.Unix(snapshot.GetValidUntilUnixS(), 0)
	for _, row := range []struct {
		name    string
		now     time.Time
		expired bool
	}{
		{"one second before issue", issued.Add(-time.Second), true},
		{"at issue", issued, false},
		{"at issue in another location", issued.In(time.FixedZone("west", -8*3600)), false},
		{"one second before expiry", until.Add(-time.Second), false},
		{"one nanosecond before expiry", until.Add(-time.Nanosecond), false},
		{"at expiry", until, true},
		{"after expiry", until.Add(time.Hour), true},
	} {
		t.Run(row.name, func(t *testing.T) {
			err := trustv1.ValidateTrustSnapshotAt(snapshot, row.now)
			switch {
			case row.expired && (!errors.Is(err, trustv1.ErrExpired) || errors.Is(err, trustv1.ErrMalformed)):
				t.Fatalf("err = %v, want ErrExpired only", err)
			case !row.expired && err != nil:
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
	broken := cloneSnapshot(snapshot)
	broken.Sha256Digest[0] ^= 1
	if err := trustv1.ValidateTrustSnapshotAt(broken, issued); !errors.Is(err, trustv1.ErrMalformed) || errors.Is(err, trustv1.ErrExpired) {
		t.Fatalf("malformed snapshot: err = %v, want ErrMalformed only", err)
	}
}

// TestJudgeSuccessor checks the monotonic install rule: a first install,
// an advance, an exact re-delivery, and each refusal class. Rollback and
// equivocation are the attacks the rule exists to stop, so each must map
// to its own error.
func TestJudgeSuccessor(t *testing.T) {
	ca := defaultCA(t, 1)
	build := func(zone string, purpose trustv1.Purpose, sequence uint64, validFor time.Duration) *trustv1.TrustSnapshot {
		generation := generationFor(ca, "gen-a")
		snapshot, err := trustv1.NewTrustSnapshot(zone, purpose, sequence, fixtureNow, fixtureNow.Add(validFor), []*trustv1.TrustGeneration{generation})
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	current := build("zone-a", trustv1.Purpose_PURPOSE_POD, 5, time.Hour)
	broken := cloneSnapshot(current)
	broken.Sha256Digest[0] ^= 1

	for _, row := range []struct {
		name          string
		current, next *trustv1.TrustSnapshot
		duplicate     bool
		want          error
	}{
		{"first install", nil, current, false, nil},
		{"advance", current, build("zone-a", trustv1.Purpose_PURPOSE_POD, 6, time.Hour), false, nil},
		{"exact re-delivery", current, cloneSnapshot(current), true, nil},
		{"rollback", current, build("zone-a", trustv1.Purpose_PURPOSE_POD, 4, time.Hour), false, trustv1.ErrRollback},
		{"equivocation", current, build("zone-a", trustv1.Purpose_PURPOSE_POD, 5, 2*time.Hour), false, trustv1.ErrEquivocation},
		{"wrong zone", current, build("zone-b", trustv1.Purpose_PURPOSE_POD, 6, time.Hour), false, trustv1.ErrWrongZone},
		{"wrong zone before rollback", current, build("zone-b", trustv1.Purpose_PURPOSE_POD, 1, time.Hour), false, trustv1.ErrWrongZone},
		{"wrong purpose", current, build("zone-a", trustv1.Purpose_PURPOSE_JOIN, 6, time.Hour), false, trustv1.ErrWrongPurpose},
		{"invalid next", current, broken, false, trustv1.ErrMalformed},
		{"absent next", current, nil, false, trustv1.ErrMalformed},
		{"invalid current", broken, current, false, trustv1.ErrMalformed},
	} {
		t.Run(row.name, func(t *testing.T) {
			duplicate, err := trustv1.JudgeSuccessor(row.current, row.next)
			if duplicate != row.duplicate {
				t.Fatalf("duplicate = %v, want %v", duplicate, row.duplicate)
			}
			if row.want == nil && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
			if row.want != nil && !errors.Is(err, row.want) {
				t.Fatalf("err = %v, want %v", err, row.want)
			}
		})
	}
}

// TestErrorClassesAreDistinct checks that no error class matches another,
// so errors.Is gives every refusal exactly one class.
func TestErrorClassesAreDistinct(t *testing.T) {
	classes := []error{
		trustv1.ErrMalformed, trustv1.ErrExpired, trustv1.ErrRollback,
		trustv1.ErrEquivocation, trustv1.ErrWrongZone, trustv1.ErrWrongPurpose,
	}
	for i, a := range classes {
		for j, b := range classes {
			if i != j && errors.Is(a, b) {
				t.Errorf("%v matches %v", a, b)
			}
		}
	}
}

// ecdsaFixtureCA mints a P-256 signing CA, which is well formed but not
// the Ed25519 CA a trust generation must be.
func ecdsaFixtureCA(t *testing.T) fixtureCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "trust fixture ECDSA CA"},
		NotBefore:             fixtureNow.Add(-time.Hour),
		NotAfter:              fixtureNow.Add(72 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return fixtureCA{der: der, certificate: certificate}
}
