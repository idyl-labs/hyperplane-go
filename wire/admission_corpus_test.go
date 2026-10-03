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

package wire_test

import (
	"encoding/json"
	"os"
	"testing"

	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	"github.com/idyl-labs/hyperplane-go/wire/internal/conformance"
)

// TestAdmissionV3ConformanceCorpus re-derives every committed vector's
// verdict and refusal class through the reference pipeline. A divergence
// means the verifier's behaviour changed, which is a wire-contract change:
// any implementation checked against the same corpus must reach the same
// verdicts. The corpus may grow, but it must not shrink or lose its
// valid vectors.
func TestAdmissionV3ConformanceCorpus(t *testing.T) {
	raw, err := os.ReadFile("testdata/admissionv3-conformance/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus conformance.Corpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Contract != apb.ZoneAdmissionLeaseContract {
		t.Fatalf("corpus contract %q, want %q", corpus.Contract, apb.ZoneAdmissionLeaseContract)
	}
	if len(corpus.Vectors) < 30 {
		t.Fatalf("corpus has %d vectors; the committed set must not shrink", len(corpus.Vectors))
	}
	seen := map[string]bool{}
	valid := 0
	for _, vector := range corpus.Vectors {
		if seen[vector.Name] {
			t.Fatalf("duplicate vector name %q", vector.Name)
		}
		seen[vector.Name] = true
		verdict, class, err := conformance.Evaluate(vector)
		if err != nil {
			t.Fatalf("vector %s: %v", vector.Name, err)
		}
		if verdict != vector.Verdict || class != vector.RefusalClass {
			t.Errorf("vector %s: got %s/%s, corpus says %s/%s",
				vector.Name, verdict, class, vector.Verdict, vector.RefusalClass)
		}
		if vector.Verdict == "valid" {
			valid++
		}
	}
	if valid < 3 {
		t.Fatalf("corpus has %d valid vectors; positives must not vanish", valid)
	}
}
