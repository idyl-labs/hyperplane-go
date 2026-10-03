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
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

// fuzzSeedSnapshots returns sealed snapshots of several shapes for seeding.
func fuzzSeedSnapshots(f *testing.F) []*trustv1.TrustSnapshot {
	f.Helper()
	two, err := trustv1.NewTrustSnapshot("zone-b", trustv1.Purpose_PURPOSE_JOIN, 9,
		fixtureNow, fixtureNow.Add(trustv1.MaxSnapshotValidity), []*trustv1.TrustGeneration{
			generationFor(defaultCA(f, 1), "gen-a"),
			generationFor(defaultCA(f, 2), "gen-b"),
		})
	if err != nil {
		f.Fatal(err)
	}
	return []*trustv1.TrustSnapshot{validSnapshot(f), two}
}

// FuzzParseCanonicalTrustSnapshotPayload checks the strict canonical JSON
// parser on arbitrary bytes. An empty digest argument stands for the
// correct digest of the payload, so the fuzzer reaches the parser's
// content checks instead of stopping at the digest. The parser must refuse
// with ErrMalformed, or return a valid snapshot whose canonical payload is
// exactly the input bytes and whose digest is SHA-256 of them.
func FuzzParseCanonicalTrustSnapshotPayload(f *testing.F) {
	for _, snapshot := range fuzzSeedSnapshots(f) {
		f.Add(snapshot.GetCanonicalPayloadJson(), []byte{})
		f.Add(snapshot.GetCanonicalPayloadJson(), snapshot.GetSha256Digest())
	}
	f.Add([]byte(`{}`), []byte{})
	f.Add([]byte(`{"zone":"zone-a"} {}`), []byte{})
	f.Fuzz(func(t *testing.T, payload, digest []byte) {
		if len(digest) == 0 {
			sum := sha256.Sum256(payload)
			digest = sum[:]
		}
		snapshot, err := trustv1.ParseCanonicalTrustSnapshotPayload(payload, digest)
		if err != nil {
			if !errors.Is(err, trustv1.ErrMalformed) || snapshot != nil {
				t.Fatalf("refusal is not a bare ErrMalformed: snapshot %v, err %v", snapshot != nil, err)
			}
			return
		}
		if len(payload) > trustv1.MaxCanonicalPayloadJSONBytes || len(snapshot.GetGenerations()) > trustv1.MaxGenerations {
			t.Fatalf("accepted snapshot exceeds a bound: %d bytes, %d generations", len(payload), len(snapshot.GetGenerations()))
		}
		canonical, err := trustv1.CanonicalTrustSnapshotPayload(snapshot)
		if err != nil || !bytes.Equal(canonical, payload) {
			t.Fatalf("accepted payload does not re-encode to itself: %v", err)
		}
		sum := sha256.Sum256(payload)
		if !bytes.Equal(snapshot.GetSha256Digest(), sum[:]) || !bytes.Equal(snapshot.GetCanonicalPayloadJson(), payload) {
			t.Fatal("accepted snapshot does not carry the payload and its digest")
		}
		if err := trustv1.ValidateTrustSnapshot(snapshot); err != nil {
			t.Fatalf("accepted snapshot does not validate: %v", err)
		}
		if duplicate, err := trustv1.JudgeSuccessor(snapshot, snapshot); err != nil || !duplicate {
			t.Fatalf("accepted snapshot is not its own duplicate: %v, %v", duplicate, err)
		}
	})
}

// FuzzValidateTrustSnapshot checks the snapshot validator on arbitrary
// protobuf bytes. A refusal must be ErrMalformed. An accepted snapshot
// must be within every bound, and its structured fields and canonical
// payload must agree: parsing the payload must reconstruct the same
// snapshot, and a deterministic re-encoding must validate again.
func FuzzValidateTrustSnapshot(f *testing.F) {
	for _, snapshot := range fuzzSeedSnapshots(f) {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(snapshot)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var snapshot trustv1.TrustSnapshot
		if err := proto.Unmarshal(data, &snapshot); err != nil {
			return
		}
		if err := trustv1.ValidateTrustSnapshot(&snapshot); err != nil {
			if !errors.Is(err, trustv1.ErrMalformed) {
				t.Fatalf("refusal is not ErrMalformed: %v", err)
			}
			return
		}
		if n := len(snapshot.GetGenerations()); n == 0 || n > trustv1.MaxGenerations {
			t.Fatalf("accepted snapshot has %d generations", n)
		}
		if len(snapshot.GetCanonicalPayloadJson()) > trustv1.MaxCanonicalPayloadJSONBytes {
			t.Fatal("accepted snapshot exceeds the payload bound")
		}
		validity := time.Duration(snapshot.GetValidUntilUnixS()-snapshot.GetIssuedAtUnixS()) * time.Second
		if validity <= 0 || validity > trustv1.MaxSnapshotValidity {
			t.Fatalf("accepted snapshot has validity %v", validity)
		}
		parsed, err := trustv1.ParseCanonicalTrustSnapshotPayload(snapshot.GetCanonicalPayloadJson(), snapshot.GetSha256Digest())
		if err != nil {
			t.Fatalf("accepted snapshot's payload does not parse: %v", err)
		}
		if !proto.Equal(parsed, &snapshot) {
			t.Fatal("accepted snapshot's payload describes a different snapshot")
		}
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&snapshot)
		if err != nil {
			t.Fatal(err)
		}
		var again trustv1.TrustSnapshot
		if err := proto.Unmarshal(encoded, &again); err != nil {
			t.Fatal(err)
		}
		if err := trustv1.ValidateTrustSnapshot(&again); err != nil {
			t.Fatalf("re-encoded snapshot does not validate: %v", err)
		}
	})
}
