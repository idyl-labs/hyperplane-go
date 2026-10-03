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
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	"github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/mintingv2"
	"github.com/idyl-labs/hyperplane-go/wire/trustv1"
)

// unknownField is a well-formed protobuf field with a number no mint
// record declares.
var unknownField = []byte{0xa0, 0x06, 0x01}

// TestEnvelopeConstants pins the envelope type names and size bounds. The
// names travel on the wire to select a record type and the bounds are
// shared with every peer, so a change to any of them is a contract change.
func TestEnvelopeConstants(t *testing.T) {
	for got, want := range map[string]string{
		mintingv2.EnvelopeTypeMintPodSvid:          "mint_pod_svid_v2_request",
		mintingv2.EnvelopeTypeMintPodSvidReply:     "mint_pod_svid_v2_response",
		mintingv2.EnvelopeTypeMintSessionSvid:      "mint_session_svid_request",
		mintingv2.EnvelopeTypeMintSessionSvidReply: "mint_session_svid_response",
	} {
		if got != want {
			t.Errorf("envelope type %q, want %q", got, want)
		}
	}
	for _, row := range []struct {
		name      string
		got, want int
	}{
		{"MaxCSRDERBytes", mintingv2.MaxCSRDERBytes, 16 * 1024},
		{"MaxCertificateDERBytes", mintingv2.MaxCertificateDERBytes, 16 * 1024},
		{"MaxCertificateChain", mintingv2.MaxCertificateChain, 4},
		{"MaxRefusalCodeBytes", mintingv2.MaxRefusalCodeBytes, 64},
	} {
		if row.got != row.want {
			t.Errorf("%s = %d, want %d", row.name, row.got, row.want)
		}
	}
}

// TestCarrierJSONShape pins the carrier's JSON form: one field named
// "record" holding the record's exact bytes in base64, so the record is
// carried without being decoded and re-encoded in transit.
func TestCarrierJSONShape(t *testing.T) {
	record := []byte{0x0a, 0x03, 0xfb, 0xff, 0x00}
	encoded, err := json.Marshal(mintingv2.Carrier{Record: record})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `{"record":"CgP7/wA="}` {
		t.Fatalf("carrier JSON = %s", encoded)
	}
	var decoded mintingv2.Carrier
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.Record) != string(record) {
		t.Fatal("carrier does not preserve the record bytes")
	}
}

// TestValidateMintPodSvidRequest checks the pod mint request profile at
// its boundaries: CSR size, pod ID text, and a positive assignment
// generation, with unknown fields refused.
func TestValidateMintPodSvidRequest(t *testing.T) {
	base := &mintingv2.MintPodSvidRequest{
		CsrDer:               []byte{0x30, 0x01, 0x01},
		PodId:                "pod-a",
		AssignmentGeneration: 1,
	}
	accept := map[string]func(*mintingv2.MintPodSvidRequest){
		"minimal":              func(*mintingv2.MintPodSvidRequest) {},
		"CSR at limit":         func(r *mintingv2.MintPodSvidRequest) { r.CsrDer = make([]byte, mintingv2.MaxCSRDERBytes) },
		"pod ID at limit":      func(r *mintingv2.MintPodSvidRequest) { r.PodId = strings.Repeat("p", admissionv3.MaxIdentifierBytes) },
		"pod ID inner space":   func(r *mintingv2.MintPodSvidRequest) { r.PodId = "pod a" },
		"large generation":     func(r *mintingv2.MintPodSvidRequest) { r.AssignmentGeneration = 1 << 62 },
		"multibyte UTF-8 text": func(r *mintingv2.MintPodSvidRequest) { r.PodId = "pod-é" },
	}
	refuse := map[string]func(*mintingv2.MintPodSvidRequest){
		"CSR absent":            func(r *mintingv2.MintPodSvidRequest) { r.CsrDer = nil },
		"CSR one byte over":     func(r *mintingv2.MintPodSvidRequest) { r.CsrDer = make([]byte, mintingv2.MaxCSRDERBytes+1) },
		"pod ID absent":         func(r *mintingv2.MintPodSvidRequest) { r.PodId = "" },
		"pod ID one byte over":  func(r *mintingv2.MintPodSvidRequest) { r.PodId = strings.Repeat("p", admissionv3.MaxIdentifierBytes+1) },
		"pod ID leading space":  func(r *mintingv2.MintPodSvidRequest) { r.PodId = " pod-a" },
		"pod ID trailing tab":   func(r *mintingv2.MintPodSvidRequest) { r.PodId = "pod-a\t" },
		"pod ID NUL":            func(r *mintingv2.MintPodSvidRequest) { r.PodId = "pod\x00a" },
		"pod ID not UTF-8":      func(r *mintingv2.MintPodSvidRequest) { r.PodId = "pod-\xff" },
		"zero generation":       func(r *mintingv2.MintPodSvidRequest) { r.AssignmentGeneration = 0 },
		"negative generation":   func(r *mintingv2.MintPodSvidRequest) { r.AssignmentGeneration = -1 },
		"unknown protobuf data": func(r *mintingv2.MintPodSvidRequest) { r.ProtoReflect().SetUnknown(unknownField) },
	}
	for name, mutate := range accept {
		request := proto.Clone(base).(*mintingv2.MintPodSvidRequest)
		mutate(request)
		if err := mintingv2.ValidateMintPodSvidRequest(request); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, mutate := range refuse {
		request := proto.Clone(base).(*mintingv2.MintPodSvidRequest)
		mutate(request)
		if err := mintingv2.ValidateMintPodSvidRequest(request); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := mintingv2.ValidateMintPodSvidRequest(nil); err == nil {
		t.Error("absent request accepted")
	}
}

// TestValidateMintSessionSvidRequest checks the session mint request
// profile: every binding fact present, a known session kind, and a grant
// ID present exactly on the proxy leg.
func TestValidateMintSessionSvidRequest(t *testing.T) {
	base := &mintingv2.MintSessionSvidRequest{
		CsrDer:               []byte{0x30, 0x01, 0x01},
		SessionId:            "session-a",
		SessionKind:          commonv2.SessionKind_SESSION_KIND_EXEC,
		SessionLeg:           commonv2.SessionLeg_SESSION_LEG_CLIENT,
		PodId:                "pod-a",
		AssignmentGeneration: 7,
		ExpiresAtUnixS:       uint64(fixtureNow.Add(time.Hour).Unix()),
	}
	proxy := func(r *mintingv2.MintSessionSvidRequest) {
		r.SessionLeg = commonv2.SessionLeg_SESSION_LEG_PROXY
		r.GrantId = "grant-a"
	}
	accept := map[string]func(*mintingv2.MintSessionSvidRequest){
		"exec client":  func(*mintingv2.MintSessionSvidRequest) {},
		"logs client":  func(r *mintingv2.MintSessionSvidRequest) { r.SessionKind = commonv2.SessionKind_SESSION_KIND_LOGS },
		"shell client": func(r *mintingv2.MintSessionSvidRequest) { r.SessionKind = commonv2.SessionKind_SESSION_KIND_SHELL },
		"exec proxy":   proxy,
		"CSR at limit": func(r *mintingv2.MintSessionSvidRequest) { r.CsrDer = make([]byte, mintingv2.MaxCSRDERBytes) },
		"grant at size": func(r *mintingv2.MintSessionSvidRequest) {
			proxy(r)
			r.GrantId = strings.Repeat("g", admissionv3.MaxIdentifierBytes)
		},
	}
	refuse := map[string]func(*mintingv2.MintSessionSvidRequest){
		"CSR absent":        func(r *mintingv2.MintSessionSvidRequest) { r.CsrDer = nil },
		"CSR one byte over": func(r *mintingv2.MintSessionSvidRequest) { r.CsrDer = make([]byte, mintingv2.MaxCSRDERBytes+1) },
		"session ID absent": func(r *mintingv2.MintSessionSvidRequest) { r.SessionId = "" },
		"session ID padded": func(r *mintingv2.MintSessionSvidRequest) { r.SessionId = "session-a " },
		"pod ID absent":     func(r *mintingv2.MintSessionSvidRequest) { r.PodId = "" },
		"pod ID one byte over": func(r *mintingv2.MintSessionSvidRequest) {
			r.PodId = strings.Repeat("p", admissionv3.MaxIdentifierBytes+1)
		},
		"zero generation": func(r *mintingv2.MintSessionSvidRequest) { r.AssignmentGeneration = 0 },
		"no expiry":       func(r *mintingv2.MintSessionSvidRequest) { r.ExpiresAtUnixS = 0 },
		"unspecified kind": func(r *mintingv2.MintSessionSvidRequest) {
			r.SessionKind = commonv2.SessionKind_SESSION_KIND_UNSPECIFIED
		},
		"unknown kind":          func(r *mintingv2.MintSessionSvidRequest) { r.SessionKind = commonv2.SessionKind(99) },
		"unspecified leg":       func(r *mintingv2.MintSessionSvidRequest) { r.SessionLeg = commonv2.SessionLeg_SESSION_LEG_UNSPECIFIED },
		"unknown leg":           func(r *mintingv2.MintSessionSvidRequest) { r.SessionLeg = commonv2.SessionLeg(9) },
		"client leg with grant": func(r *mintingv2.MintSessionSvidRequest) { r.GrantId = "grant-a" },
		"proxy leg no grant":    func(r *mintingv2.MintSessionSvidRequest) { proxy(r); r.GrantId = "" },
		"proxy grant padded":    func(r *mintingv2.MintSessionSvidRequest) { proxy(r); r.GrantId = " grant-a" },
		"proxy grant over": func(r *mintingv2.MintSessionSvidRequest) {
			proxy(r)
			r.GrantId = strings.Repeat("g", admissionv3.MaxIdentifierBytes+1)
		},
		"unknown protobuf data": func(r *mintingv2.MintSessionSvidRequest) { r.ProtoReflect().SetUnknown(unknownField) },
	}
	for name, mutate := range accept {
		request := proto.Clone(base).(*mintingv2.MintSessionSvidRequest)
		mutate(request)
		if err := mintingv2.ValidateMintSessionSvidRequest(request); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
	for name, mutate := range refuse {
		request := proto.Clone(base).(*mintingv2.MintSessionSvidRequest)
		mutate(request)
		if err := mintingv2.ValidateMintSessionSvidRequest(request); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := mintingv2.ValidateMintSessionSvidRequest(nil); err == nil {
		t.Error("absent request accepted")
	}
}

// TestValidatePodCredentialGenerationAccepts checks the shapes of a
// legitimate pod mint: a leaf backdated before its snapshot was issued, a
// leaf issued after the snapshot, a chain through an intermediate up to
// the chain limit, the largest lease, and renewal instants one second
// inside each end of the credential interval.
func TestValidatePodCredentialGenerationAccepts(t *testing.T) {
	m := newMintFixture(t)
	intermediate := newCA(t, 2, &m.root)
	viaIntermediate := newLeaf(t, &intermediate, fixtureNow.Add(-time.Minute), fixtureNow.Add(12*time.Hour))
	afterIssue := newLeaf(t, &m.root, fixtureNow.Add(10*time.Minute), fixtureNow.Add(12*time.Hour))

	for name, mutate := range map[string]func(*mintingv2.PodCredentialGeneration){
		"backdated leaf":   func(*mintingv2.PodCredentialGeneration) {},
		"leaf after issue": func(g *mintingv2.PodCredentialGeneration) { g.CertDer = [][]byte{afterIssue.der} },
		"intermediate chain": func(g *mintingv2.PodCredentialGeneration) {
			g.CertDer = [][]byte{viaIntermediate.der, intermediate.der}
		},
		"chain at limit": func(g *mintingv2.PodCredentialGeneration) {
			g.CertDer = [][]byte{viaIntermediate.der, intermediate.der, intermediate.der, intermediate.der}
		},
		"lease at limit":   func(g *mintingv2.PodCredentialGeneration) { g.LeaseEnvelope = maxLease },
		"earliest renewal": func(g *mintingv2.PodCredentialGeneration) { g.RenewAtUnixS = m.notBefore + 1 },
		"latest renewal":   func(g *mintingv2.PodCredentialGeneration) { g.RenewAtUnixS = m.notAfter - 1 },
		"late renewal": func(g *mintingv2.PodCredentialGeneration) {
			g.RenewAtUnixS = uint64(fixtureNow.Add(11 * time.Hour).Unix())
		},
	} {
		generation := m.podGeneration()
		mutate(generation)
		if err := mintingv2.ValidatePodCredentialGeneration(generation, m.notBefore, m.notAfter); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

// TestCredentialGenerationRefusals checks that a credential generation is
// accepted only as a complete, self-consistent unit. The same refusal
// matrix applies to pod and session generations, since both pair a chain
// and lease with the POD snapshot their issuer belongs to.
func TestCredentialGenerationRefusals(t *testing.T) {
	m := newMintFixture(t)
	otherRoot := newCA(t, 3, nil)
	strangerLeaf := newLeaf(t, &otherRoot, fixtureNow.Add(-time.Minute), fixtureNow.Add(12*time.Hour))
	lateLeaf := newLeaf(t, &m.root, fixtureNow.Add(2*time.Hour), fixtureNow.Add(12*time.Hour))
	staleLeaf := newLeaf(t, &m.root, fixtureNow.Add(-3*time.Hour), fixtureNow.Add(-time.Hour))
	joinSnapshot := snapshotFor(t, trustv1.Purpose_PURPOSE_JOIN, m.root)
	brokenSnapshot := proto.Clone(m.snapshot).(*trustv1.TrustSnapshot)
	brokenSnapshot.Sha256Digest[0] ^= 1

	type parts struct {
		chain    [][]byte
		lease    []byte
		snapshot *trustv1.TrustSnapshot
	}
	for _, row := range []struct {
		name    string
		mutate  func(*parts)
		expired bool
	}{
		{name: "chain absent", mutate: func(p *parts) { p.chain = nil }},
		{name: "chain over limit", mutate: func(p *parts) {
			p.chain = [][]byte{m.leaf.der, m.root.der, m.root.der, m.root.der, m.root.der}
		}},
		{name: "empty certificate", mutate: func(p *parts) { p.chain = [][]byte{m.leaf.der, {}} }},
		{name: "certificate over limit", mutate: func(p *parts) {
			p.chain = [][]byte{m.leaf.der, make([]byte, mintingv2.MaxCertificateDERBytes+1)}
		}},
		{name: "lease absent", mutate: func(p *parts) { p.lease = nil }},
		{name: "lease over limit", mutate: func(p *parts) { p.lease = append(append([]byte(nil), maxLease...), 0) }},
		{name: "leaf not DER", mutate: func(p *parts) { p.chain = [][]byte{{0x30, 0x00}} }},
		{name: "intermediate not DER", mutate: func(p *parts) { p.chain = [][]byte{m.leaf.der, {0x30, 0x00}} }},
		{name: "snapshot absent", mutate: func(p *parts) { p.snapshot = nil }},
		{name: "snapshot malformed", mutate: func(p *parts) { p.snapshot = brokenSnapshot }},
		{name: "JOIN snapshot", mutate: func(p *parts) { p.snapshot = joinSnapshot }},
		{name: "issuer absent from snapshot", mutate: func(p *parts) { p.chain = [][]byte{strangerLeaf.der} }},
		{name: "leaf expired before snapshot", mutate: func(p *parts) { p.chain = [][]byte{staleLeaf.der} }},
		{name: "snapshot expired before leaf", expired: true, mutate: func(p *parts) { p.chain = [][]byte{lateLeaf.der} }},
	} {
		t.Run(row.name, func(t *testing.T) {
			p := parts{chain: [][]byte{m.leaf.der}, lease: m.lease, snapshot: m.snapshot}
			row.mutate(&p)
			pod := &mintingv2.PodCredentialGeneration{
				CertDer: p.chain, LeaseEnvelope: p.lease, TrustSnapshot: p.snapshot,
				RenewAtUnixS: uint64(fixtureNow.Add(6 * time.Hour).Unix()),
			}
			podErr := mintingv2.ValidatePodCredentialGeneration(pod, m.notBefore, m.notAfter)
			session := &mintingv2.SessionCredentialGeneration{CertDer: p.chain, LeaseEnvelope: p.lease, TrustSnapshot: p.snapshot}
			sessionErr := mintingv2.ValidateSessionCredentialGeneration(session)
			if podErr == nil || sessionErr == nil {
				t.Fatalf("accepted: pod %v, session %v", podErr, sessionErr)
			}
			if row.expired && (!errors.Is(podErr, trustv1.ErrExpired) || !errors.Is(sessionErr, trustv1.ErrExpired)) {
				t.Fatalf("expired pairing is not ErrExpired: pod %v, session %v", podErr, sessionErr)
			}
		})
	}
}

// TestValidatePodCredentialGenerationRenewalWindow checks that renewal
// must fall strictly inside the credential interval: renewing at either
// end, or outside it, is refused.
func TestValidatePodCredentialGenerationRenewalWindow(t *testing.T) {
	m := newMintFixture(t)
	for name, renewAt := range map[string]uint64{
		"zero":             0,
		"before interval":  m.notBefore - 1,
		"at not_before":    m.notBefore,
		"at not_after":     m.notAfter,
		"after not_after":  m.notAfter + 1,
		"far after expiry": ^uint64(0),
	} {
		generation := m.podGeneration()
		generation.RenewAtUnixS = renewAt
		if err := mintingv2.ValidatePodCredentialGeneration(generation, m.notBefore, m.notAfter); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestCredentialGenerationsRefuseUnknownAndAbsent checks the remaining
// whole-record refusals: an absent generation and one carrying unknown
// protobuf fields.
func TestCredentialGenerationsRefuseUnknownAndAbsent(t *testing.T) {
	m := newMintFixture(t)
	if err := mintingv2.ValidatePodCredentialGeneration(nil, m.notBefore, m.notAfter); err == nil {
		t.Error("absent pod generation accepted")
	}
	if err := mintingv2.ValidateSessionCredentialGeneration(nil); err == nil {
		t.Error("absent session generation accepted")
	}
	pod := m.podGeneration()
	pod.ProtoReflect().SetUnknown(unknownField)
	if err := mintingv2.ValidatePodCredentialGeneration(pod, m.notBefore, m.notAfter); err == nil {
		t.Error("pod generation with unknown fields accepted")
	}
	session := m.sessionGeneration()
	session.ProtoReflect().SetUnknown(unknownField)
	if err := mintingv2.ValidateSessionCredentialGeneration(session); err == nil {
		t.Error("session generation with unknown fields accepted")
	}
	if err := mintingv2.ValidateSessionCredentialGeneration(m.sessionGeneration()); err != nil {
		t.Errorf("honest session generation refused: %v", err)
	}
}

// refusalCodes lists refusal codes with whether a reply may carry them:
// one to MaxRefusalCodeBytes bytes of lowercase ASCII letters and hyphens.
var refusalCodes = map[string]bool{
	"rate-limited": true,
	"-":            true,
	strings.Repeat("a", mintingv2.MaxRefusalCodeBytes): true,
	"": false,
	strings.Repeat("a", mintingv2.MaxRefusalCodeBytes+1): false,
	"Rate-limited":  false,
	"rate_limited":  false,
	"rate limited":  false,
	"rate-limited ": false,
	"retry2":        false,
	"réessayer":     false,
	"rate\x00":      false,
}

// TestValidateMintPodSvidReply checks that a pod mint reply carries
// exactly one verdict, each validated in full, and that a refusal code is
// a short machine-readable token.
func TestValidateMintPodSvidReply(t *testing.T) {
	m := newMintFixture(t)
	generationReply := &mintingv2.MintPodSvidReply{Verdict: &mintingv2.MintPodSvidReply_Generation{Generation: m.podGeneration()}}
	if err := mintingv2.ValidateMintPodSvidReply(generationReply, m.notBefore, m.notAfter); err != nil {
		t.Fatalf("honest generation reply refused: %v", err)
	}
	for code, valid := range refusalCodes {
		reply := &mintingv2.MintPodSvidReply{Verdict: &mintingv2.MintPodSvidReply_Refusal{Refusal: &mintingv2.Refusal{Code: code}}}
		if err := mintingv2.ValidateMintPodSvidReply(reply, m.notBefore, m.notAfter); (err == nil) != valid {
			t.Errorf("refusal code %q: err %v, want valid %v", code, err, valid)
		}
	}
	badGeneration := m.podGeneration()
	badGeneration.RenewAtUnixS = m.notAfter
	unknownRefusal := &mintingv2.Refusal{Code: "denied"}
	unknownRefusal.ProtoReflect().SetUnknown(unknownField)
	unknownReply := proto.Clone(generationReply).(*mintingv2.MintPodSvidReply)
	unknownReply.ProtoReflect().SetUnknown(unknownField)
	for name, reply := range map[string]*mintingv2.MintPodSvidReply{
		"absent":              nil,
		"no verdict":          {},
		"nil generation":      {Verdict: &mintingv2.MintPodSvidReply_Generation{}},
		"nil refusal":         {Verdict: &mintingv2.MintPodSvidReply_Refusal{}},
		"invalid generation":  {Verdict: &mintingv2.MintPodSvidReply_Generation{Generation: badGeneration}},
		"refusal unknown":     {Verdict: &mintingv2.MintPodSvidReply_Refusal{Refusal: unknownRefusal}},
		"reply unknown field": unknownReply,
	} {
		if err := mintingv2.ValidateMintPodSvidReply(reply, m.notBefore, m.notAfter); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestValidateMintSessionSvidReply applies the same single-verdict rule to
// session mint replies.
func TestValidateMintSessionSvidReply(t *testing.T) {
	m := newMintFixture(t)
	generationReply := &mintingv2.MintSessionSvidReply{Verdict: &mintingv2.MintSessionSvidReply_Generation{Generation: m.sessionGeneration()}}
	if err := mintingv2.ValidateMintSessionSvidReply(generationReply); err != nil {
		t.Fatalf("honest generation reply refused: %v", err)
	}
	for code, valid := range refusalCodes {
		reply := &mintingv2.MintSessionSvidReply{Verdict: &mintingv2.MintSessionSvidReply_Refusal{Refusal: &mintingv2.Refusal{Code: code}}}
		if err := mintingv2.ValidateMintSessionSvidReply(reply); (err == nil) != valid {
			t.Errorf("refusal code %q: err %v, want valid %v", code, err, valid)
		}
	}
	badGeneration := m.sessionGeneration()
	badGeneration.TrustSnapshot = nil
	unknownReply := proto.Clone(generationReply).(*mintingv2.MintSessionSvidReply)
	unknownReply.ProtoReflect().SetUnknown(unknownField)
	for name, reply := range map[string]*mintingv2.MintSessionSvidReply{
		"absent":              nil,
		"no verdict":          {},
		"nil generation":      {Verdict: &mintingv2.MintSessionSvidReply_Generation{}},
		"nil refusal":         {Verdict: &mintingv2.MintSessionSvidReply_Refusal{}},
		"invalid generation":  {Verdict: &mintingv2.MintSessionSvidReply_Generation{Generation: badGeneration}},
		"reply unknown field": unknownReply,
	} {
		if err := mintingv2.ValidateMintSessionSvidReply(reply); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestValidatorsDoNotMutateInput checks that validation is read-only: a
// validated record is byte-for-byte the record the caller passed, so a
// caller can forward the exact bytes it validated.
func TestValidatorsDoNotMutateInput(t *testing.T) {
	m := newMintFixture(t)
	reply := &mintingv2.MintPodSvidReply{Verdict: &mintingv2.MintPodSvidReply_Generation{Generation: m.podGeneration()}}
	before := proto.Clone(reply)
	if err := mintingv2.ValidateMintPodSvidReply(reply, m.notBefore, m.notAfter); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(before, reply) {
		t.Fatal("validation changed the reply")
	}
}
