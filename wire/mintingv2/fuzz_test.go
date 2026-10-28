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
	"strings"
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
	checkChainAndLease(t, chain, lease)
	if err := trustv1.ValidateTrustSnapshot(snapshot); err != nil || snapshot.GetPurpose() != trustv1.Purpose_PURPOSE_POD {
		t.Fatalf("accepted generation pairs with snapshot %v (%v)", snapshot.GetPurpose(), err)
	}
}

// checkChainAndLease asserts the chain and lease bounds every accepted
// credential generation is within.
func checkChainAndLease(t *testing.T, chain [][]byte, lease []byte) {
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

// FuzzValidateMintDataDockSvidReply checks the data dock reply validator
// under the same properties as the pod reply validator. An accepted
// generation also names its edge as host:port and by a SPIFFE ID, and
// carries one to MaxEdgeRoots bounded roots.
func FuzzValidateMintDataDockSvidReply(f *testing.F) {
	m := newMintFixture(f)
	f.Add(mustMarshal(f, &mintingv2.MintDataDockSvidReply{Verdict: &mintingv2.MintDataDockSvidReply_Generation{Generation: m.dataDockGeneration()}}), m.notBefore, m.notAfter)
	f.Add(mustMarshal(f, &mintingv2.MintDataDockSvidReply{Verdict: &mintingv2.MintDataDockSvidReply_Refusal{Refusal: &mintingv2.Refusal{Code: "node-not-eligible"}}}), m.notBefore, m.notAfter)
	f.Add([]byte{}, uint64(0), uint64(0))
	f.Fuzz(func(t *testing.T, data []byte, notBefore, notAfter uint64) {
		var reply mintingv2.MintDataDockSvidReply
		if err := proto.Unmarshal(data, &reply); err != nil {
			return
		}
		before := proto.Clone(&reply)
		err := mintingv2.ValidateMintDataDockSvidReply(&reply, notBefore, notAfter)
		if !proto.Equal(before, &reply) {
			t.Fatal("validation changed the reply")
		}
		if err != nil {
			return
		}
		switch verdict := reply.GetVerdict().(type) {
		case *mintingv2.MintDataDockSvidReply_Refusal:
			checkRefusalCode(t, verdict.Refusal.GetCode())
		case *mintingv2.MintDataDockSvidReply_Generation:
			generation := verdict.Generation
			checkChainAndLease(t, generation.GetCertDer(), generation.GetLeaseEnvelope())
			if generation.GetRenewAtUnixS() <= notBefore || generation.GetRenewAtUnixS() >= notAfter {
				t.Fatalf("accepted renewal %d outside (%d, %d)", generation.GetRenewAtUnixS(), notBefore, notAfter)
			}
			if host, port, ok := strings.Cut(generation.GetEdgeEndpoint(), ":"); !ok || host == "" || port == "" {
				t.Fatalf("accepted edge endpoint %q", generation.GetEdgeEndpoint())
			}
			if !strings.HasPrefix(generation.GetEdgePrincipal(), "spiffe://") {
				t.Fatalf("accepted edge principal %q", generation.GetEdgePrincipal())
			}
			roots := generation.GetEdgeRootsDer()
			if len(roots) == 0 || len(roots) > mintingv2.MaxEdgeRoots {
				t.Fatalf("accepted %d edge roots", len(roots))
			}
			for _, root := range roots {
				if len(root) == 0 || len(root) > mintingv2.MaxCertificateDERBytes {
					t.Fatalf("accepted edge root of %d bytes", len(root))
				}
			}
		default:
			t.Fatal("accepted reply without a verdict")
		}
		var again mintingv2.MintDataDockSvidReply
		if err := proto.Unmarshal(mustMarshal(t, &reply), &again); err != nil {
			t.Fatal(err)
		}
		if err := mintingv2.ValidateMintDataDockSvidReply(&again, notBefore, notAfter); err != nil {
			t.Fatalf("re-encoded reply refused: %v", err)
		}
	})
}
