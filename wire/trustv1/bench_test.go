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
	"fmt"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

func maxGenerationSnapshot(b *testing.B) *trustv1.TrustSnapshot {
	b.Helper()
	generations := make([]*trustv1.TrustGeneration, 0, trustv1.MaxGenerations)
	for i := range trustv1.MaxGenerations {
		generations = append(generations, generationFor(defaultCA(b, byte(i+1)), fmt.Sprintf("gen-%02d", i)))
	}
	snapshot, err := trustv1.NewTrustSnapshot("zone-a", trustv1.Purpose_PURPOSE_POD, 1,
		fixtureNow, fixtureNow.Add(time.Hour), generations)
	if err != nil {
		b.Fatal(err)
	}
	return snapshot
}

// BenchmarkValidateTrustSnapshot measures validating a one-generation
// snapshot, the common case a consumer checks on every delivery.
func BenchmarkValidateTrustSnapshot(b *testing.B) {
	snapshot := validSnapshot(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(snapshot.GetCanonicalPayloadJson())))
	for b.Loop() {
		if err := trustv1.ValidateTrustSnapshot(snapshot); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValidateTrustSnapshotMaxGenerations measures the worst case the
// bounds allow: a snapshot with MaxGenerations certificates.
func BenchmarkValidateTrustSnapshotMaxGenerations(b *testing.B) {
	snapshot := maxGenerationSnapshot(b)
	b.ReportAllocs()
	b.SetBytes(int64(len(snapshot.GetCanonicalPayloadJson())))
	for b.Loop() {
		if err := trustv1.ValidateTrustSnapshot(snapshot); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkParseCanonicalTrustSnapshotPayload measures the strict parse of
// a received canonical payload, including its validation.
func BenchmarkParseCanonicalTrustSnapshotPayload(b *testing.B) {
	snapshot := validSnapshot(b)
	payload, digest := snapshot.GetCanonicalPayloadJson(), snapshot.GetSha256Digest()
	b.ReportAllocs()
	b.SetBytes(int64(len(payload)))
	for b.Loop() {
		if _, err := trustv1.ParseCanonicalTrustSnapshotPayload(payload, digest); err != nil {
			b.Fatal(err)
		}
	}
}
