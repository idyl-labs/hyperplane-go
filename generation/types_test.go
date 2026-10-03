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

package generation

import (
	"fmt"
	"strings"
	"testing"
)

// TestEdgeTagStringRendersIncarnationSlashLease pins the documented
// incarnation/lease_id rendering. The tag is the unit of invalidation, so
// two tags that differ in either part must render differently.
func TestEdgeTagStringRendersIncarnationSlashLease(t *testing.T) {
	for _, row := range []struct {
		tag  EdgeTag
		want string
	}{
		{EdgeTag{Incarnation: "edge-a", LeaseID: "lease-1"}, "edge-a/lease-1"},
		{EdgeTag{Incarnation: "edge-a", LeaseID: "lease-2"}, "edge-a/lease-2"},
		{EdgeTag{Incarnation: "edge-b", LeaseID: "lease-1"}, "edge-b/lease-1"},
		{EdgeTag{}, "/"},
	} {
		if got := row.tag.String(); got != row.want {
			t.Errorf("%#v.String() = %q, want %q", row.tag, got, row.want)
		}
	}
}

// TestEdgeTagFormatsThroughStringer checks that the fmt verbs a caller
// uses for logs pick up the String method, so a tag is never rendered as a
// raw struct with field names.
func TestEdgeTagFormatsThroughStringer(t *testing.T) {
	tag := EdgeTag{Incarnation: "edge-a", LeaseID: "lease-1"}
	for _, verb := range []string{"%v", "%s"} {
		if got := fmt.Sprintf(verb, tag); got != "edge-a/lease-1" {
			t.Errorf("Sprintf(%q) = %q", verb, got)
		}
	}
}

// TestDockGenStringRendersEdgeSlotEpochNonce pins the debugging rendering
// edge_tag#slot.epoch.nonce, including the zero value and the extremes of
// the counters, so the format is stable for tests that compare it.
func TestDockGenStringRendersEdgeSlotEpochNonce(t *testing.T) {
	edge := EdgeTag{Incarnation: "edge-a", LeaseID: "lease-1"}
	for _, row := range []struct {
		gen  DockGen
		want string
	}{
		{DockGen{Edge: edge, Slot: 3, Epoch: 9, Nonce: "n0"}, "edge-a/lease-1#3.9.n0"},
		{DockGen{}, "/#0.0."},
		{DockGen{Edge: edge, Slot: ^uint64(0), Epoch: ^uint64(0), Nonce: "n1"}, "edge-a/lease-1#18446744073709551615.18446744073709551615.n1"},
	} {
		if got := row.gen.String(); got != row.want {
			t.Errorf("%#v.String() = %q, want %q", row.gen, got, row.want)
		}
	}
}

// TestDockGenEdgeRenderingOmitsNonce checks the rendering the type
// documents for output: a generation's edge tag, slot and epoch never
// include the nonce, because the nonce is a succession credential that
// must not reach logs or errors.
func TestDockGenEdgeRenderingOmitsNonce(t *testing.T) {
	const nonce = "nonce-secret-value"
	gen := DockGen{Edge: EdgeTag{Incarnation: "edge-a", LeaseID: "lease-1"}, Slot: 2, Epoch: 5, Nonce: nonce}
	safe := fmt.Sprintf("%s#%d.%d", gen.Edge, gen.Slot, gen.Epoch)
	if safe != "edge-a/lease-1#2.5" {
		t.Fatalf("safe rendering = %q", safe)
	}
	if strings.Contains(safe, nonce) || strings.Contains(gen.Edge.String(), nonce) {
		t.Fatal("output rendering carries the nonce")
	}
	if !strings.HasSuffix(gen.String(), "."+nonce) {
		t.Fatalf("debug rendering %q does not end with the nonce", gen.String())
	}
}

// TestDockGenEqualityIncludesNonce checks that two generations differing
// only in nonce are distinct values, so state keyed by DockGen never
// carries from one dock to another.
func TestDockGenEqualityIncludesNonce(t *testing.T) {
	edge := EdgeTag{Incarnation: "edge-a", LeaseID: "lease-1"}
	a := DockGen{Edge: edge, Slot: 1, Epoch: 1, Nonce: "n-a"}
	b := DockGen{Edge: edge, Slot: 1, Epoch: 1, Nonce: "n-b"}
	if a == b {
		t.Fatal("generations with different nonces compare equal")
	}
	state := map[DockGen]int{a: 1}
	if _, ok := state[b]; ok {
		t.Fatal("state recorded for one generation applies to another")
	}
}
