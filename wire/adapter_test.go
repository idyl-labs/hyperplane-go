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
	"slices"
	"testing"

	"github.com/idyl-labs/hyperplane-go/wire"
)

// TestAdapterClassBitPositionsArePinned checks every named adapter class
// against its fixed bit. Bit positions are a wire contract: reassigning one
// would silently change what an existing lease grants.
func TestAdapterClassBitPositionsArePinned(t *testing.T) {
	pinned := []struct {
		name string
		bit  uint
	}{
		{wire.AdapterControlDock, 0},
		{wire.AdapterRPC, 1},
		{wire.AdapterStream, 2},
		{wire.AdapterFlow, 3},
		{wire.AdapterIngressTarget, 4},
		{wire.AdapterSplice, 5},
		{wire.AdapterFederation, 6},
	}
	for _, p := range pinned {
		got, err := wire.AdapterClassesToBits([]string{p.name})
		if err != nil {
			t.Fatalf("%s: %v", p.name, err)
		}
		if got != 1<<p.bit {
			t.Errorf("%s = %#x, want bit %d", p.name, got, p.bit)
		}
		if names := wire.AdapterClassesFromBits(1 << p.bit); !slices.Equal(names, []string{p.name}) {
			t.Errorf("bit %d renders as %q, want %q", p.bit, names, p.name)
		}
	}
	if got, _ := wire.AdapterClassesToBits([]string{wire.AdapterStream}); got != wire.LaneClassStream {
		t.Error("the stream adapter class and the stream lane class must share a bit")
	}
	if got, _ := wire.AdapterClassesToBits([]string{wire.AdapterSplice}); got != wire.LaneClassSpliceLeg {
		t.Error("the splice adapter class and the splice-leg lane class must share a bit")
	}
}

// TestAdapterClassesFromBitsRendersAscendingWithSynthetic checks the
// canonical in-memory form: names in ascending bit order, unnamed bits as
// adapter(N), and the empty set as nil.
func TestAdapterClassesFromBitsRendersAscendingWithSynthetic(t *testing.T) {
	if got := wire.AdapterClassesFromBits(0); got != nil {
		t.Fatalf("empty mask = %q, want nil", got)
	}
	got := wire.AdapterClassesFromBits(1<<63 | 1<<7 | 1<<2 | 1<<0)
	want := []string{wire.AdapterControlDock, wire.AdapterStream, "adapter(7)", "adapter(63)"}
	if !slices.Equal(got, want) {
		t.Fatalf("rendering = %q, want %q", got, want)
	}
}

// TestAdapterClassesRoundTripEveryBit checks that every single bit, and the
// full mask, survive a render and parse unchanged, so a receiver never
// loses a class it has no name for.
func TestAdapterClassesRoundTripEveryBit(t *testing.T) {
	masks := []uint64{^uint64(0)}
	for bit := range 64 {
		masks = append(masks, 1<<bit)
	}
	for _, mask := range masks {
		got, err := wire.AdapterClassesToBits(wire.AdapterClassesFromBits(mask))
		if err != nil {
			t.Fatalf("mask %#x: %v", mask, err)
		}
		if got != mask {
			t.Fatalf("mask %#x round-tripped to %#x", mask, got)
		}
	}
}

// TestAdapterClassesToBitsAcceptsSyntheticAndDuplicates checks that the
// synthetic rendering of a named bit parses to that bit, and that naming a
// class twice sets its bit once.
func TestAdapterClassesToBitsAcceptsSyntheticAndDuplicates(t *testing.T) {
	got, err := wire.AdapterClassesToBits([]string{"adapter(0)", wire.AdapterControlDock, "adapter(40)"})
	if err != nil {
		t.Fatal(err)
	}
	if got != 1|1<<40 {
		t.Fatalf("mask = %#x, want %#x", got, uint64(1|1<<40))
	}
	if got, err := wire.AdapterClassesToBits(nil); err != nil || got != 0 {
		t.Fatalf("no names = %#x, %v; want 0, nil", got, err)
	}
}

// TestAdapterClassesToBitsRefusesUnknownNames checks that a name with no
// bit assignment is an explicit error, never a silent drop: unknown names,
// out-of-range bits, and every non-exact synthetic spelling.
func TestAdapterClassesToBitsRefusesUnknownNames(t *testing.T) {
	for _, name := range []string{
		"",
		"unknown",
		"Stream",
		" stream",
		"adapter(64)",
		"adapter(-1)",
		"adapter(07)",
		"adapter(+7)",
		"adapter( 7)",
		"adapter(7",
		"adapter7)",
		"adapter()",
		"Adapter(7)",
		"lane(7)",
		"adapter(9223372036854775808)",
	} {
		got, err := wire.AdapterClassesToBits([]string{wire.AdapterRPC, name})
		if err == nil {
			t.Errorf("%q accepted as mask %#x", name, got)
			continue
		}
		if got != 0 {
			t.Errorf("%q: refusal returned mask %#x, want 0", name, got)
		}
	}
}

// Synthetic and ParseSynthetic round-trip every non-negative value, and
// ParseSynthetic accepts nothing but the exact rendering.
func TestSyntheticRoundTrip(t *testing.T) {
	for _, n := range []int64{0, 1, 9, 63, 1 << 40, 1<<63 - 1} {
		s := wire.Synthetic("reason", n)
		got, ok := wire.ParseSynthetic(s, "reason")
		if !ok || got != n {
			t.Errorf("ParseSynthetic(%q) = %d, %v; want %d", s, got, ok, n)
		}
	}
	if got := wire.Synthetic("adapter", 9); got != "adapter(9)" {
		t.Errorf("Synthetic = %q, want adapter(9)", got)
	}
	for _, s := range []string{
		"reason(-1)", "reason(+1)", "reason(01)", "reason( 1)", "reason()", "reason(1", "reason1)",
		"other(1)", "reason(1)x", "xreason(1)", "reason(9223372036854775808)", "",
	} {
		if n, ok := wire.ParseSynthetic(s, "reason"); ok {
			t.Errorf("ParseSynthetic(%q) accepted as %d", s, n)
		}
	}
}
