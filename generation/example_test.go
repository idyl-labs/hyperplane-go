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

package generation_test

import (
	"fmt"

	"github.com/idyl-labs/hyperplane-go/generation"
)

// ExampleDockGen renders a dock generation for output as edge_tag#slot.epoch,
// leaving out the nonce, which is a credential.
func ExampleDockGen() {
	gen := generation.DockGen{
		Edge:  generation.EdgeTag{Incarnation: "edge-a", LeaseID: "lease-1"},
		Slot:  4,
		Epoch: 2,
		Nonce: "never-logged",
	}
	fmt.Printf("%s#%d.%d\n", gen.Edge, gen.Slot, gen.Epoch)
	// Output:
	// edge-a/lease-1#4.2
}
