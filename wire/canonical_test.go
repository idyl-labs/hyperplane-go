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
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
)

// unknownVarintField is field 4095 with varint value 1: a field no
// canonical message defines.
var unknownVarintField = protoreflect.RawFields{0xf8, 0xff, 0x01, 0x01}

func canonicalTestProof() *apb.DockProofInput {
	return &apb.DockProofInput{
		Version:             apb.DockProofVersion,
		DockContract:        apb.DockContract,
		ExporterLabel:       apb.TLSExporterLabel,
		ExporterValue:       bytes.Repeat([]byte{0x44}, apb.TLSExporterBytes),
		LeaseEnvelopeSha256: bytes.Repeat([]byte{0xab}, apb.SHA256Bytes),
		KeepaliveMs:         20_000,
		PredecessorGen: &mpb.DockGen{
			Edge:      &mpb.EdgeTag{Incarnation: []byte("edge-a"), LeaseId: []byte("lease-a")},
			Slot:      7,
			SlotEpoch: 9,
			Nonce:     []byte("nonce-000001"),
		},
	}
}

// TestMarshalCanonicalRefusesUnknownFieldsAtAnyDepth checks that unknown
// bytes anywhere in the message tree are refused. The deterministic
// marshal would re-emit them in an order this encoder does not control, so
// a message carrying them has no canonical form to sign.
func TestMarshalCanonicalRefusesUnknownFieldsAtAnyDepth(t *testing.T) {
	clean := canonicalTestProof()
	first, err := wire.MarshalCanonical(clean)
	if err != nil {
		t.Fatal(err)
	}
	second, err := wire.MarshalCanonical(proto.Clone(clean))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("canonical encoding of equal messages differs")
	}

	for name, taint := range map[string]func(*apb.DockProofInput){
		"root":       func(m *apb.DockProofInput) { m.ProtoReflect().SetUnknown(unknownVarintField) },
		"nested":     func(m *apb.DockProofInput) { m.PredecessorGen.ProtoReflect().SetUnknown(unknownVarintField) },
		"two levels": func(m *apb.DockProofInput) { m.PredecessorGen.Edge.ProtoReflect().SetUnknown(unknownVarintField) },
	} {
		m := canonicalTestProof()
		taint(m)
		if raw, err := wire.MarshalCanonical(m); err == nil {
			t.Errorf("%s unknown field encoded as %x", name, raw)
		}
	}
}

// TestMarshalCanonicalWalksListsAndMaps checks that the unknown-field walk
// descends through repeated message fields and message-valued maps, so the
// canonical check never depends on the shape of the message being signed.
func TestMarshalCanonicalWalksListsAndMaps(t *testing.T) {
	build := func() *structpb.Struct {
		inner, err := structpb.NewStruct(map[string]any{"leaf": "value"})
		if err != nil {
			t.Fatal(err)
		}
		return &structpb.Struct{Fields: map[string]*structpb.Value{
			"list":   structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{structpb.NewStringValue("a"), structpb.NewStructValue(inner)}}),
			"scalar": structpb.NewNumberValue(1),
		}}
	}
	if _, err := wire.MarshalCanonical(build()); err != nil {
		t.Fatalf("clean map and list message refused: %v", err)
	}

	inMap := build()
	inMap.Fields["scalar"].ProtoReflect().SetUnknown(unknownVarintField)
	if _, err := wire.MarshalCanonical(inMap); err == nil {
		t.Error("unknown field inside a map value was encoded")
	}

	inList := build()
	inList.Fields["list"].GetListValue().Values[0].ProtoReflect().SetUnknown(unknownVarintField)
	if _, err := wire.MarshalCanonical(inList); err == nil {
		t.Error("unknown field inside a list element was encoded")
	}

	deep := build()
	deep.Fields["list"].GetListValue().Values[1].GetStructValue().Fields["leaf"].ProtoReflect().SetUnknown(unknownVarintField)
	if _, err := wire.MarshalCanonical(deep); err == nil {
		t.Error("unknown field below a list element and a map value was encoded")
	}
}
