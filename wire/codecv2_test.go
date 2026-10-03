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
	"math"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/generation"
	"github.com/idyl-labs/hyperplane-go/wire"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
)

// codecTestNonce is distinctive so a leak into any rendering is visible.
const codecTestNonce = "secret-nonce-value"

func codecTestGen() generation.DockGen {
	return generation.DockGen{
		Edge:  generation.EdgeTag{Incarnation: "edge-a", LeaseID: "lease-a"},
		Slot:  7,
		Epoch: 9,
		Nonce: codecTestNonce,
	}
}

// TestGenProtoV2RoundTrip checks that converting a generation to its wire
// form and back is lossless, byte for byte, including binary identifiers
// that are not valid UTF-8.
func TestGenProtoV2RoundTrip(t *testing.T) {
	for _, g := range []generation.DockGen{
		codecTestGen(),
		{Edge: generation.EdgeTag{Incarnation: "\x00\xff\xfe", LeaseID: "\x80"}, Slot: math.MaxUint32, Epoch: math.MaxUint32, Nonce: "\x00\x01"},
		{},
	} {
		p, err := wire.GenToProtoV2(g)
		if err != nil {
			t.Fatalf("%s: %v", wire.RedactGen(g), err)
		}
		if got := wire.GenFromProtoV2(p); got != g {
			t.Fatalf("round trip of %s changed it to %s", wire.RedactGen(g), wire.RedactGen(got))
		}
	}
}

// TestGenToProtoV2WireForm checks the exact wire field mapping, so a peer
// reading the protobuf sees the slot epoch in slot_epoch and the nonce
// bytes unchanged.
func TestGenToProtoV2WireForm(t *testing.T) {
	p, err := wire.GenToProtoV2(codecTestGen())
	if err != nil {
		t.Fatal(err)
	}
	want := &mpb.DockGen{
		Edge:      &mpb.EdgeTag{Incarnation: []byte("edge-a"), LeaseId: []byte("lease-a")},
		Slot:      7,
		SlotEpoch: 9,
		Nonce:     []byte(codecTestNonce),
	}
	if !proto.Equal(p, want) {
		t.Fatalf("wire form = %v, want %v", p, want)
	}
	if got := wire.TagFromProtoV2(wire.TagToProtoV2(codecTestGen().Edge)); got != codecTestGen().Edge {
		t.Fatalf("edge tag round trip = %v", got)
	}
}

// TestFromProtoV2NilIsZero checks that an absent wire generation or edge
// tag converts to the zero value instead of panicking, since both are
// optional message fields.
func TestFromProtoV2NilIsZero(t *testing.T) {
	if got := wire.GenFromProtoV2(nil); got != (generation.DockGen{}) {
		t.Fatalf("nil generation = %+v, want zero", got)
	}
	if got := wire.TagFromProtoV2(nil); got != (generation.EdgeTag{}) {
		t.Fatalf("nil tag = %+v, want zero", got)
	}
	if got := wire.GenFromProtoV2(&mpb.DockGen{Slot: 3}); got != (generation.DockGen{Slot: 3}) {
		t.Fatalf("generation without an edge = %+v", got)
	}
}

// TestGenToProtoV2RefusesValuesPastU32 checks that a slot or epoch that
// does not fit the 32-bit wire field is refused rather than truncated, and
// that the refusal does not reveal the nonce.
func TestGenToProtoV2RefusesValuesPastU32(t *testing.T) {
	for name, mutate := range map[string]func(*generation.DockGen){
		"slot":  func(g *generation.DockGen) { g.Slot = math.MaxUint32 + 1 },
		"epoch": func(g *generation.DockGen) { g.Epoch = math.MaxUint32 + 1 },
	} {
		g := codecTestGen()
		mutate(&g)
		p, err := wire.GenToProtoV2(g)
		if err == nil {
			t.Fatalf("%s past u32 converted to %v", name, p)
		}
		if strings.Contains(err.Error(), codecTestNonce) {
			t.Fatalf("%s refusal reveals the nonce: %v", name, err)
		}
	}
}

// TestRedactGenOmitsNonce checks the one safe rendering of a generation:
// edge tag, slot and epoch, never the nonce, which is the generation's
// succession credential. DockGen.String does include it, which is why
// RedactGen exists.
func TestRedactGenOmitsNonce(t *testing.T) {
	g := codecTestGen()
	got := wire.RedactGen(g)
	if got != "edge-a/lease-a#7.9" {
		t.Fatalf("RedactGen = %q, want %q", got, "edge-a/lease-a#7.9")
	}
	if strings.Contains(got, codecTestNonce) {
		t.Fatal("RedactGen output contains the nonce")
	}
	if !strings.Contains(g.String(), codecTestNonce) {
		t.Fatal("test premise: DockGen.String is expected to carry the nonce")
	}
	other := g
	other.Nonce = "a-different-nonce"
	if wire.RedactGen(other) != got {
		t.Fatal("RedactGen output depends on the nonce")
	}
}

// TestRedactGenHexEncodesNonPrintable checks that a binary or non-ASCII
// identifier is hex-encoded, so a rendering never carries control bytes
// into a log line, while printable ASCII passes through unchanged.
func TestRedactGenHexEncodesNonPrintable(t *testing.T) {
	cases := []struct {
		incarnation, leaseID, want string
	}{
		{"\x00\xff", "lease-a", "00ff/lease-a#1.2"},
		{"edge-a", "line\nbreak", "edge-a/6c696e650a627265616b#1.2"},
		{"café", "", "636166c3a9/#1.2"},
		{"~!@ {}", "x", "~!@ {}/x#1.2"},
	}
	for _, tc := range cases {
		g := generation.DockGen{Edge: generation.EdgeTag{Incarnation: tc.incarnation, LeaseID: tc.leaseID}, Slot: 1, Epoch: 2}
		if got := wire.RedactGen(g); got != tc.want {
			t.Errorf("RedactGen(%q, %q) = %q, want %q", tc.incarnation, tc.leaseID, got, tc.want)
		}
	}
}
