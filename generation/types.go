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
)

// EdgeTag identifies one edge incarnation serving under one route lease.
// It is the unit of invalidation when an edge ends: once that incarnation
// stops serving under that lease, every dock generation that names the tag
// ends with it.
type EdgeTag struct {
	Incarnation string
	LeaseID     string
}

// String renders the tag as incarnation/lease_id.
func (t EdgeTag) String() string { return t.Incarnation + "/" + t.LeaseID }

// DockGen identifies one dock generation. State recorded for one
// generation never applies to another. The nonce makes generations
// globally unique: one generation is exactly one dock.
//
// The nonce is the succession credential: a client that names its
// previous generation, nonce included, makes its next dock a succession.
// The edge discloses it only inside the dock's own TLS connection. It
// must never appear in logs, errors, metrics or any other output; render
// a generation as edge_tag#slot.epoch.
type DockGen struct {
	Edge  EdgeTag
	Slot  uint64
	Epoch uint64
	Nonce string
}

// String renders the generation including its nonce, for tests and local
// debugging only. Because the nonce is a credential, String must never be
// used for logs, errors or other output.
func (g DockGen) String() string {
	return fmt.Sprintf("%s#%d.%d.%s", g.Edge, g.Slot, g.Epoch, g.Nonce)
}
