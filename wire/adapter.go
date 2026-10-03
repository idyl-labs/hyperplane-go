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

package wire

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
)

// Adapter classes name the kinds of traffic an endpoint may carry. On the
// wire they form a u64 bitset (for example the adapter_classes mask of an
// admission lease); each class has a fixed bit position, noted beside its
// name. Bit positions are never reassigned: a new adapter class takes a
// new bit.
const (
	AdapterControlDock   = "control-dock"   // bit 0
	AdapterRPC           = "rpc"            // bit 1
	AdapterStream        = "stream"         // bit 2
	AdapterFlow          = "flow"           // bit 3
	AdapterIngressTarget = "ingress-target" // bit 4
	AdapterSplice        = "splice"         // bit 5
	AdapterFederation    = "federation"     // bit 6
)

// adapterNames is indexed by bit position.
var adapterNames = []string{
	AdapterControlDock,
	AdapterRPC,
	AdapterStream,
	AdapterFlow,
	AdapterIngressTarget,
	AdapterSplice,
	AdapterFederation,
}

// AdapterClassesToBits maps canonical adapter-class names (plus the
// synthetic "adapter(N)" rendering of bits this package has no name for)
// to the wire bitset. An unknown name is an explicit error, never a
// silent drop.
func AdapterClassesToBits(names []string) (uint64, error) {
	var b uint64
	for _, name := range names {
		bit := -1
		for i, n := range adapterNames {
			if n == name {
				bit = i
				break
			}
		}
		if bit < 0 {
			n, ok := parseSynthetic(name, "adapter")
			if !ok || n < 0 || n > 63 {
				return 0, fmt.Errorf("wire: adapter class %q has no bit assignment", name)
			}
			bit = int(n)
		}
		b |= 1 << bit
	}
	return b, nil
}

// AdapterClassesFromBits renders a wire bitset as canonical names in
// ascending bit order, which is the canonical in-memory form. Bits without
// a name render synthetically as "adapter(N)" and survive a round trip
// through AdapterClassesToBits unchanged.
func AdapterClassesFromBits(b uint64) []string {
	if b == 0 {
		return nil
	}
	out := make([]string, 0, bits.OnesCount64(b))
	for i := range 64 {
		if b&(1<<i) == 0 {
			continue
		}
		if i < len(adapterNames) {
			out = append(out, adapterNames[i])
		} else {
			out = append(out, synthetic("adapter", int64(i)))
		}
	}
	return out
}

// synthetic renders an unnamed wire value so it round-trips without loss:
// decode produces it, encode parses it back to the same wire value.
func synthetic(prefix string, n int64) string {
	return fmt.Sprintf("%s(%d)", prefix, n)
}

// parseSynthetic inverts synthetic. The format is strict: anything that is
// not exactly the synthetic rendering of some value is rejected.
func parseSynthetic(s, prefix string) (int64, bool) {
	if !strings.HasPrefix(s, prefix+"(") || !strings.HasSuffix(s, ")") {
		return 0, false
	}
	n, err := strconv.ParseInt(s[len(prefix)+1:len(s)-1], 10, 64)
	if err != nil || n < 0 || synthetic(prefix, n) != s {
		return 0, false
	}
	return n, true
}
