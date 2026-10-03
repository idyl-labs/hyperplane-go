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

	"github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/mintingv2"
)

// BenchmarkValidateMintPodSvidReply measures validating a successful pod
// mint reply: chain and lease bounds, the paired snapshot, and the leaf's
// verification against it.
func BenchmarkValidateMintPodSvidReply(b *testing.B) {
	m := newMintFixture(b)
	reply := &mintingv2.MintPodSvidReply{Verdict: &mintingv2.MintPodSvidReply_Generation{Generation: m.podGeneration()}}
	b.ReportAllocs()
	for b.Loop() {
		if err := mintingv2.ValidateMintPodSvidReply(reply, m.notBefore, m.notAfter); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkValidateMintSessionSvidRequest measures the request check a
// minting service applies before it does any signing work.
func BenchmarkValidateMintSessionSvidRequest(b *testing.B) {
	request := &mintingv2.MintSessionSvidRequest{
		CsrDer:               make([]byte, 512),
		SessionId:            "session-a",
		SessionKind:          commonv2.SessionKind_SESSION_KIND_EXEC,
		SessionLeg:           commonv2.SessionLeg_SESSION_LEG_PROXY,
		PodId:                "pod-a",
		AssignmentGeneration: 7,
		GrantId:              "grant-a",
		ExpiresAtUnixS:       uint64(fixtureNow.Unix()),
	}
	if err := mintingv2.ValidateMintSessionSvidRequest(request); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if err := mintingv2.ValidateMintSessionSvidRequest(request); err != nil {
			b.Fatal(err)
		}
	}
}
