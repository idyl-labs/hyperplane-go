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
	"math"

	dc "github.com/idyl-labs/hyperplane-go/generation"
	pbv2 "github.com/idyl-labs/hyperplane-go/wire/commonv2"
)

// codecv2.go: conversions between the generated protobuf edge tag and
// dock generation and their in-memory forms. Edge-tag fields and the nonce
// are opaque bytes on the wire and strings in memory; the conversion copies
// them byte for byte.

// TagToProtoV2 converts an in-memory edge tag to its wire form.
func TagToProtoV2(t dc.EdgeTag) *pbv2.EdgeTag {
	return &pbv2.EdgeTag{Incarnation: []byte(t.Incarnation), LeaseId: []byte(t.LeaseID)}
}

// TagFromProtoV2 converts a wire edge tag to its in-memory form. A nil tag
// converts to the zero EdgeTag.
func TagFromProtoV2(p *pbv2.EdgeTag) dc.EdgeTag {
	if p == nil {
		return dc.EdgeTag{}
	}
	return dc.EdgeTag{Incarnation: string(p.GetIncarnation()), LeaseID: string(p.GetLeaseId())}
}

// GenToProtoV2 converts an in-memory generation to its wire form. The wire
// slot and epoch are 32 bits wide; a generation whose slot or epoch does
// not fit is refused rather than truncated.
func GenToProtoV2(g dc.DockGen) (*pbv2.DockGen, error) {
	if g.Slot > math.MaxUint32 || g.Epoch > math.MaxUint32 {
		return nil, fmt.Errorf("wire: generation %s slot/epoch exceeds u32", RedactGen(g))
	}
	return &pbv2.DockGen{
		Edge:      TagToProtoV2(g.Edge),
		Slot:      uint32(g.Slot),
		SlotEpoch: uint32(g.Epoch),
		Nonce:     []byte(g.Nonce),
	}, nil
}

// GenFromProtoV2 converts a wire generation to its in-memory form. A nil
// generation converts to the zero DockGen.
func GenFromProtoV2(p *pbv2.DockGen) dc.DockGen {
	if p == nil {
		return dc.DockGen{}
	}
	return dc.DockGen{
		Edge:  TagFromProtoV2(p.GetEdge()),
		Slot:  uint64(p.GetSlot()),
		Epoch: uint64(p.GetSlotEpoch()),
		Nonce: string(p.GetNonce()),
	}
}
