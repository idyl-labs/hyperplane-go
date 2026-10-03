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
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	"github.com/idyl-labs/hyperplane-go/wire/mintingv2"
	"github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

func mustMarshal(tb testing.TB, message proto.Message) []byte {
	tb.Helper()
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		tb.Fatal(err)
	}
	return encoded
}

// checkRefusalCode asserts the refusal-code profile on an accepted reply.
func checkRefusalCode(t *testing.T, code string) {
	t.Helper()
	if code == "" || len(code) > mintingv2.MaxRefusalCodeBytes {
		t.Fatalf("accepted refusal code of %d bytes", len(code))
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && r != '-' {
			t.Fatalf("accepted refusal code %q", code)
		}
	}
}

// checkGenerationParts asserts the bounds every accepted credential
// generation is within, and that it pairs with a valid POD snapshot.
func checkGenerationParts(t *testing.T, chain [][]byte, lease []byte, snapshot *trustv1.TrustSnapshot) {
	t.Helper()
	if len(chain) == 0 || len(chain) > mintingv2.MaxCertificateChain {
		t.Fatalf("accepted chain of %d certificates", len(chain))
	}
	for _, certificate := range chain {
		if len(certificate) == 0 || len(certificate) > mintingv2.MaxCertificateDERBytes {
			t.Fatalf("accepted certificate of %d bytes", len(certificate))
		}
	}
	if len(lease) == 0 || len(lease) > admissionv3.MaxLeaseEnvelopeBytes {
		t.Fatalf("accepted lease of %d bytes", len(lease))
	}
	if err := trustv1.ValidateTrustSnapshot(snapshot); err != nil || snapshot.GetPurpose() != trustv1.Purpose_PURPOSE_POD {
		t.Fatalf("accepted generation pairs with snapshot %v (%v)", snapshot.GetPurpose(), err)
	}
}

// FuzzValidateMintPodSvidReply checks the pod reply validator on arbitrary
// protobuf bytes and credential intervals. It must never panic or change
// its input. An accepted reply carries exactly one verdict: a refusal code
// within the code profile, or a generation within every bound with a
// renewal instant strictly inside the interval. A deterministic
// re-encoding of an accepted reply must be accepted again.
func FuzzValidateMintPodSvidReply(f *testing.F) {
	m := newMintFixture(f)
	f.Add(mustMarshal(f, &mintingv2.MintPodSvidReply{Verdict: &mintingv2.MintPodSvidReply_Generation{Generation: m.podGeneration()}}), m.notBefore, m.notAfter)
	f.Add(mustMarshal(f, &mintingv2.MintPodSvidReply{Verdict: &mintingv2.MintPodSvidReply_Refusal{Refusal: &mintingv2.Refusal{Code: "rate-limited"}}}), m.notBefore, m.notAfter)
	f.Add([]byte{}, uint64(0), uint64(0))
	f.Fuzz(func(t *testing.T, data []byte, notBefore, notAfter uint64) {
		var reply mintingv2.MintPodSvidReply
		if err := proto.Unmarshal(data, &reply); err != nil {
			return
		}
		before := proto.Clone(&reply)
		err := mintingv2.ValidateMintPodSvidReply(&reply, notBefore, notAfter)
		if !proto.Equal(before, &reply) {
			t.Fatal("validation changed the reply")
		}
		if err != nil {
			return
		}
		switch verdict := reply.GetVerdict().(type) {
		case *mintingv2.MintPodSvidReply_Refusal:
			checkRefusalCode(t, verdict.Refusal.GetCode())
		case *mintingv2.MintPodSvidReply_Generation:
			generation := verdict.Generation
			checkGenerationParts(t, generation.GetCertDer(), generation.GetLeaseEnvelope(), generation.GetTrustSnapshot())
			if generation.GetRenewAtUnixS() <= notBefore || generation.GetRenewAtUnixS() >= notAfter {
				t.Fatalf("accepted renewal %d outside (%d, %d)", generation.GetRenewAtUnixS(), notBefore, notAfter)
			}
		default:
			t.Fatal("accepted reply without a verdict")
		}
		var again mintingv2.MintPodSvidReply
		if err := proto.Unmarshal(mustMarshal(t, &reply), &again); err != nil {
			t.Fatal(err)
		}
		if err := mintingv2.ValidateMintPodSvidReply(&again, notBefore, notAfter); err != nil {
			t.Fatalf("re-encoded reply refused: %v", err)
		}
	})
}

// FuzzValidateMintSessionSvidReply checks the session reply validator
// under the same properties as the pod reply validator.
func FuzzValidateMintSessionSvidReply(f *testing.F) {
	m := newMintFixture(f)
	f.Add(mustMarshal(f, &mintingv2.MintSessionSvidReply{Verdict: &mintingv2.MintSessionSvidReply_Generation{Generation: m.sessionGeneration()}}))
	f.Add(mustMarshal(f, &mintingv2.MintSessionSvidReply{Verdict: &mintingv2.MintSessionSvidReply_Refusal{Refusal: &mintingv2.Refusal{Code: "denied"}}}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		var reply mintingv2.MintSessionSvidReply
		if err := proto.Unmarshal(data, &reply); err != nil {
			return
		}
		before := proto.Clone(&reply)
		err := mintingv2.ValidateMintSessionSvidReply(&reply)
		if !proto.Equal(before, &reply) {
			t.Fatal("validation changed the reply")
		}
		if err != nil {
			return
		}
		switch verdict := reply.GetVerdict().(type) {
		case *mintingv2.MintSessionSvidReply_Refusal:
			checkRefusalCode(t, verdict.Refusal.GetCode())
		case *mintingv2.MintSessionSvidReply_Generation:
			generation := verdict.Generation
			checkGenerationParts(t, generation.GetCertDer(), generation.GetLeaseEnvelope(), generation.GetTrustSnapshot())
		default:
			t.Fatal("accepted reply without a verdict")
		}
		var again mintingv2.MintSessionSvidReply
		if err := proto.Unmarshal(mustMarshal(t, &reply), &again); err != nil {
			t.Fatal(err)
		}
		if err := mintingv2.ValidateMintSessionSvidReply(&again); err != nil {
			t.Fatalf("re-encoded reply refused: %v", err)
		}
	})
}
