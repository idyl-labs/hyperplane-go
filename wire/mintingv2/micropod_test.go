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
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/mintingv2"
)

// TestMintSessionSvidRequestMicropodSequenceIsRequestIdentity checks that
// the sequence is part of the request: two requests that differ only in it
// encode to different deterministic bytes, and a request without it
// encodes exactly as it did before the field existed.
func TestMintSessionSvidRequestMicropodSequenceIsRequestIdentity(t *testing.T) {
	ordinary := &mintingv2.MintSessionSvidRequest{
		CsrDer:               []byte{0x30, 0x01, 0x01},
		SessionId:            "session-a",
		SessionKind:          commonv2.SessionKind_SESSION_KIND_EXEC,
		SessionLeg:           commonv2.SessionLeg_SESSION_LEG_CLIENT,
		PodId:                "pod-a",
		AssignmentGeneration: 7,
		ExpiresAtUnixS:       1_700_003_600,
	}
	micropod := proto.Clone(ordinary).(*mintingv2.MintSessionSvidRequest)
	micropod.MicropodSequence = 7
	other := proto.Clone(ordinary).(*mintingv2.MintSessionSvidRequest)
	other.MicropodSequence = 8
	encode := func(m proto.Message) []byte {
		t.Helper()
		raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	ordinaryRaw, micropodRaw, otherRaw := encode(ordinary), encode(micropod), encode(other)
	if bytes.Equal(ordinaryRaw, micropodRaw) || bytes.Equal(micropodRaw, otherRaw) {
		t.Fatal("requests differing only in the Micropod sequence encode identically")
	}

	previous := dynamicpb.NewMessage(previousSessionRequestDescriptor(t))
	if err := proto.Unmarshal(ordinaryRaw, previous); err != nil {
		t.Fatal(err)
	}
	if len(previous.GetUnknown()) != 0 || !bytes.Equal(encode(previous), ordinaryRaw) {
		t.Fatal("a request without a sequence encodes differently under the previous contract")
	}
}

// TestMintSessionSvidRequestMicropodRefusedByPreviousContract checks that
// an issuer built before the field existed cannot accept a Micropod
// request: field 9 decodes as unknown content, which every validator in
// this package refuses.
func TestMintSessionSvidRequestMicropodRefusedByPreviousContract(t *testing.T) {
	request := &mintingv2.MintSessionSvidRequest{
		CsrDer:               []byte{0x30, 0x01, 0x01},
		SessionId:            "session-a",
		SessionKind:          commonv2.SessionKind_SESSION_KIND_SHELL,
		SessionLeg:           commonv2.SessionLeg_SESSION_LEG_CLIENT,
		PodId:                "pod-a",
		AssignmentGeneration: 7,
		ExpiresAtUnixS:       1_700_003_600,
		MicropodSequence:     7,
	}
	if err := mintingv2.ValidateMintSessionSvidRequest(request); err != nil {
		t.Fatalf("Micropod request refused: %v", err)
	}
	raw, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	previous := dynamicpb.NewMessage(previousSessionRequestDescriptor(t))
	if err := proto.Unmarshal(raw, previous); err != nil {
		t.Fatal(err)
	}
	if len(previous.GetUnknown()) == 0 {
		t.Fatal("the previous contract decoded the sequence as a known field")
	}

	// The same unknown bytes on the current message are refused by the
	// current validator, which is the rule the previous validator applied.
	withUnknown := proto.Clone(request).(*mintingv2.MintSessionSvidRequest)
	withUnknown.MicropodSequence = 0
	withUnknown.ProtoReflect().SetUnknown(previous.GetUnknown())
	if err := mintingv2.ValidateMintSessionSvidRequest(withUnknown); err == nil {
		t.Fatal("a request carrying the sequence as unknown content was accepted")
	}
}

// previousSessionRequestDescriptor is MintSessionSvidRequest as it was
// before micropod_sequence: the current descriptor with field 9 removed.
func previousSessionRequestDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := protodesc.ToFileDescriptorProto(mintingv2.File_idyl_minting_v2_minting_proto)
	found := false
	for _, message := range file.GetMessageType() {
		if message.GetName() != "MintSessionSvidRequest" {
			continue
		}
		kept := message.Field[:0]
		for _, field := range message.GetField() {
			if field.GetNumber() == 9 {
				found = true
				continue
			}
			kept = append(kept, field)
		}
		message.Field = kept
	}
	if !found {
		t.Fatal("MintSessionSvidRequest has no field 9")
	}
	previous, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	return previous.Messages().ByName("MintSessionSvidRequest")
}
