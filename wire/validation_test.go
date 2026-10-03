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
	"bytes"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
)

// RejectUnknown refuses unknown fields at the root and at every nested
// depth, and accepts the same message without them.
func TestRejectUnknownAtAnyDepth(t *testing.T) {
	if err := wire.RejectUnknown(canonicalTestProof().ProtoReflect()); err != nil {
		t.Fatalf("clean message refused: %v", err)
	}
	for name, taint := range map[string]func(*apb.DockProofInput){
		"root":       func(m *apb.DockProofInput) { m.ProtoReflect().SetUnknown(unknownVarintField) },
		"nested":     func(m *apb.DockProofInput) { m.PredecessorGen.ProtoReflect().SetUnknown(unknownVarintField) },
		"two levels": func(m *apb.DockProofInput) { m.PredecessorGen.Edge.ProtoReflect().SetUnknown(unknownVarintField) },
	} {
		m := canonicalTestProof()
		taint(m)
		if err := wire.RejectUnknown(m.ProtoReflect()); err == nil {
			t.Errorf("%s unknown field accepted", name)
		}
	}
}

// UnmarshalCanonical accepts exactly the canonical encoding. A duplicated
// field decodes to the same message but is not its canonical encoding, so
// it is refused as non-canonical; size and decoding failures are refused
// as malformed, and the name labels the error.
func TestUnmarshalCanonical(t *testing.T) {
	raw, err := wire.MarshalCanonical(canonicalTestProof())
	if err != nil {
		t.Fatal(err)
	}
	var got apb.DockProofInput
	if err := wire.UnmarshalCanonical(raw, &got, len(raw), "proof"); err != nil {
		t.Fatalf("canonical input refused: %v", err)
	}
	if !proto.Equal(&got, canonicalTestProof()) {
		t.Fatal("decoded message differs from the encoded one")
	}

	again, err := proto.Marshal(&apb.DockProofInput{KeepaliveMs: canonicalTestProof().GetKeepaliveMs()})
	if err != nil {
		t.Fatal(err)
	}
	duplicated := append(bytes.Clone(raw), again...)
	cases := []struct {
		name string
		raw  []byte
		max  int
		want error
	}{
		{"empty", nil, 1024, wire.ErrAdmissionMalformed},
		{"over the bound", raw, len(raw) - 1, wire.ErrAdmissionMalformed},
		{"truncated", raw[:len(raw)-1], 1024, wire.ErrAdmissionMalformed},
		{"unknown field", append(bytes.Clone(raw), 0xf8, 0xff, 0x01, 0x01), 1024, wire.ErrAdmissionMalformed},
		{"duplicated field", duplicated, 1024, wire.ErrAdmissionNonCanonical},
	}
	for _, tc := range cases {
		var m apb.DockProofInput
		err := wire.UnmarshalCanonical(tc.raw, &m, tc.max, "proof")
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
			continue
		}
		if !strings.Contains(err.Error(), "proof") {
			t.Errorf("%s: error %q does not name the input", tc.name, err)
		}
	}
}

// ValidateDockGeneration accepts one exact generation and refuses each
// incomplete or out-of-bounds field with ErrAdmissionMalformed.
func TestValidateDockGeneration(t *testing.T) {
	valid := func() *mpb.DockGen {
		return &mpb.DockGen{
			Edge:  &mpb.EdgeTag{Incarnation: []byte("edge-a"), LeaseId: []byte("lease-a")},
			Slot:  7,
			Nonce: bytes.Repeat([]byte{0x01}, apb.DockGenerationNonceBytes),
		}
	}
	if err := wire.ValidateDockGeneration(valid()); err != nil {
		t.Fatalf("exact generation refused: %v", err)
	}
	long := bytes.Repeat([]byte{'x'}, apb.MaxIdentifierBytes+1)
	for name, mutate := range map[string]func(*mpb.DockGen) *mpb.DockGen{
		"nil":               func(*mpb.DockGen) *mpb.DockGen { return nil },
		"no edge":           func(g *mpb.DockGen) *mpb.DockGen { g.Edge = nil; return g },
		"empty incarnation": func(g *mpb.DockGen) *mpb.DockGen { g.Edge.Incarnation = nil; return g },
		"long incarnation":  func(g *mpb.DockGen) *mpb.DockGen { g.Edge.Incarnation = long; return g },
		"empty lease id":    func(g *mpb.DockGen) *mpb.DockGen { g.Edge.LeaseId = nil; return g },
		"long lease id":     func(g *mpb.DockGen) *mpb.DockGen { g.Edge.LeaseId = long; return g },
		"zero slot":         func(g *mpb.DockGen) *mpb.DockGen { g.Slot = 0; return g },
		"short nonce":       func(g *mpb.DockGen) *mpb.DockGen { g.Nonce = g.Nonce[1:]; return g },
		"long nonce":        func(g *mpb.DockGen) *mpb.DockGen { g.Nonce = append(g.Nonce, 0x01); return g },
	} {
		if err := wire.ValidateDockGeneration(mutate(valid())); !errors.Is(err, wire.ErrAdmissionMalformed) {
			t.Errorf("%s: %v, want ErrAdmissionMalformed", name, err)
		}
	}
}

// ValidateTrustDomain accepts lowercase DNS-label trust domains and
// refuses every other spelling.
func TestValidateTrustDomain(t *testing.T) {
	for _, td := range []string{
		"example.com", "z1.zone.example.com", "a", "a-1.b2", strings.Repeat("a", 63) + ".example.com",
	} {
		if err := wire.ValidateTrustDomain(td); err != nil {
			t.Errorf("%q refused: %v", td, err)
		}
	}
	for _, td := range []string{
		"", " example.com", "example.com ", "Example.com", "example..com", ".example.com",
		"example.com.", "-a.example.com", "a-.example.com", "a_b.example.com", "example.com:443",
		strings.Repeat("a", 64) + ".example.com", strings.Repeat("a.", 127) + "aa",
	} {
		if err := wire.ValidateTrustDomain(td); err == nil {
			t.Errorf("%q accepted", td)
		}
	}
}
