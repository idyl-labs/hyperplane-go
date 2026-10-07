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
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
)

const (
	micropodPodID = "33333333-3333-3333-3333-333333333333"
	// micropodPathPrefix is every session path segment up to and including
	// the pod incarnation of refusalSessionPayload.
	micropodPathPrefix = "spiffe://z1.zone.example.com/subnet/subnet-1/account/acct-1/namespace/11111111-1111-1111-1111-111111111111/workload/22222222-2222-2222-2222-222222222222/pod/" + micropodPodID + "/pod-instance/" + micropodPodID + ".7"
)

// micropodSessionPrincipal renders a session principal whose micropod
// segment is spelled exactly as given.
func micropodSessionPrincipal(sequence, kind, leg string) string {
	return micropodPathPrefix + "/micropod/" + sequence + "/session/" + kind + "/session-1/leg/" + leg
}

// micropodSessionPayload is one complete client-leg exec session lease
// that targets Micropod 7 of its Pod.
func micropodSessionPayload() *apb.ZoneAdmissionLeasePayload {
	payload := refusalSessionPayload()
	payload.MicropodSequence = 7
	payload.Principal = micropodSessionPrincipal("7", "exec", "client")
	return payload
}

// TestZoneAdmissionLeaseMicropodSessionProfile checks the accepted shapes
// of a Micropod session: exec and shell, both legs, and the smallest and
// largest sequence, each bound to an authenticated peer that presents the
// same principal.
func TestZoneAdmissionLeaseMicropodSessionProfile(t *testing.T) {
	rows := []struct {
		name     string
		kind     mpb.SessionKind
		leg      mpb.SessionLeg
		sequence uint64
	}{
		{"exec client", mpb.SessionKind_SESSION_KIND_EXEC, mpb.SessionLeg_SESSION_LEG_CLIENT, 7},
		{"exec proxy", mpb.SessionKind_SESSION_KIND_EXEC, mpb.SessionLeg_SESSION_LEG_PROXY, 7},
		{"shell client", mpb.SessionKind_SESSION_KIND_SHELL, mpb.SessionLeg_SESSION_LEG_CLIENT, 7},
		{"shell proxy", mpb.SessionKind_SESSION_KIND_SHELL, mpb.SessionLeg_SESSION_LEG_PROXY, 7},
		{"smallest sequence", mpb.SessionKind_SESSION_KIND_EXEC, mpb.SessionLeg_SESSION_LEG_CLIENT, 1},
		{"largest sequence", mpb.SessionKind_SESSION_KIND_EXEC, mpb.SessionLeg_SESSION_LEG_CLIENT, apb.MaxMicropodSequence},
	}
	for _, row := range rows {
		payload := refusalSessionPayload()
		payload.SessionKind = row.kind
		payload.SessionLeg = row.leg
		if row.leg == mpb.SessionLeg_SESSION_LEG_PROXY {
			payload.GrantId = "grant-1"
		}
		payload.MicropodSequence = row.sequence
		kind := strings.ToLower(strings.TrimPrefix(row.kind.String(), "SESSION_KIND_"))
		leg := strings.ToLower(strings.TrimPrefix(row.leg.String(), "SESSION_LEG_"))
		payload.Principal = micropodSessionPrincipal(strconv.FormatUint(row.sequence, 10), kind, leg)
		if err := wire.ValidateZoneAdmissionLeasePayload(payload, payload.GetIssuedAtUnixS()); err != nil {
			t.Errorf("%s: refused: %v", row.name, err)
			continue
		}
		peer := wire.LeasePeer{
			Principal: payload.Principal, SubjectSPKISHA256: payload.SubjectSpkiSha256,
			Zone: payload.Zone, FabricPlane: payload.FabricPlane, EndpointKind: payload.EndpointKind,
			SVIDNotAfterUnixS: payload.NotAfterUnixS, GrantNotAfterUnixS: payload.NotAfterUnixS,
		}
		if err := wire.ValidateZoneAdmissionLeaseBinding(payload, peer); err != nil {
			t.Errorf("%s: binding refused: %v", row.name, err)
		}
		for _, other := range []string{
			strings.Replace(payload.Principal, "/micropod/"+strconv.FormatUint(row.sequence, 10), "", 1),
			micropodSessionPrincipal(strconv.FormatUint(row.sequence+1, 10), kind, leg),
		} {
			peer.Principal = other
			if err := wire.ValidateZoneAdmissionLeaseBinding(payload, peer); !errors.Is(err, wire.ErrAdmissionBinding) {
				t.Errorf("%s: peer %q: err = %v, want ErrAdmissionBinding", row.name, other, err)
			}
		}
	}
}

// TestZoneAdmissionLeaseMicropodSessionRefusals checks that the lease and
// the principal must carry the same sequence, that only the unique decimal
// spelling in the fixed position matches, and that only exec and shell
// session leases may carry a sequence. Each refusal is malformed: no form
// is translated into another.
func TestZoneAdmissionLeaseMicropodSessionRefusals(t *testing.T) {
	principal := func(sequence string) func(*apb.ZoneAdmissionLeasePayload) {
		return func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = micropodSessionPrincipal(sequence, "exec", "client")
		}
	}
	assertPayloadRefusals(t, micropodSessionPayload(), []payloadMutation{
		{"principal names another sequence", principal("8")},
		{"lease names another sequence", func(p *apb.ZoneAdmissionLeasePayload) { p.MicropodSequence = 8 }},
		{"lease omits the sequence", func(p *apb.ZoneAdmissionLeasePayload) { p.MicropodSequence = 0 }},
		{"principal omits the sequence", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = strings.Replace(p.Principal, "/micropod/7", "", 1)
		}},
		{"leading zero", principal("07")},
		{"plus sign", principal("+7")},
		{"minus sign", principal("-7")},
		{"hexadecimal", principal("0x7")},
		{"exponent", principal("7e0")},
		{"fraction", principal("7.0")},
		{"non-ASCII digit", principal("٧")},
		{"zero spelled in a lease without a sequence", func(p *apb.ZoneAdmissionLeasePayload) {
			p.MicropodSequence = 0
			p.Principal = micropodSessionPrincipal("0", "exec", "client")
		}},
		{"sequence above the maximum", func(p *apb.ZoneAdmissionLeasePayload) {
			p.MicropodSequence = apb.MaxMicropodSequence + 1
			p.Principal = micropodSessionPrincipal(strconv.FormatUint(apb.MaxMicropodSequence+1, 10), "exec", "client")
		}},
		{"largest uint64", func(p *apb.ZoneAdmissionLeasePayload) {
			p.MicropodSequence = ^uint64(0)
			p.Principal = micropodSessionPrincipal(strconv.FormatUint(^uint64(0), 10), "exec", "client")
		}},
		{"keyword misspelled", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = strings.Replace(p.Principal, "/micropod/", "/micropods/", 1)
		}},
		{"keyword capitalized", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = strings.Replace(p.Principal, "/micropod/", "/Micropod/", 1)
		}},
		{"segment after the session", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = micropodPathPrefix + "/session/exec/session-1/micropod/7/leg/client"
		}},
		{"segment before the incarnation", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = strings.Replace(
				micropodPathPrefix, "/pod-instance/", "/micropod/7/pod-instance/", 1,
			) + "/session/exec/session-1/leg/client"
		}},
		{"segment repeated", func(p *apb.ZoneAdmissionLeasePayload) {
			p.Principal = strings.Replace(p.Principal, "/micropod/7/", "/micropod/7/micropod/7/", 1)
		}},
		{"logs session", func(p *apb.ZoneAdmissionLeasePayload) {
			p.SessionKind = mpb.SessionKind_SESSION_KIND_LOGS
			p.Principal = micropodSessionPrincipal("7", "logs", "client")
		}},
		{"unknown session kind", func(p *apb.ZoneAdmissionLeasePayload) { p.SessionKind = mpb.SessionKind(99) }},
	})

	withSequence := func(p *apb.ZoneAdmissionLeasePayload) { p.MicropodSequence = 7 }
	for name, base := range map[string]*apb.ZoneAdmissionLeasePayload{
		"node":  refusalNodePayload(),
		"pod":   goldenPodPayload(),
		"share": shareLeasePayload(),
	} {
		t.Run(name, func(t *testing.T) {
			assertPayloadRefusals(t, base, []payloadMutation{{name + " lease with a sequence", withSequence}})
		})
	}
}

// TestZoneAdmissionLeaseOrdinarySessionUnchanged checks that a session
// lease without a sequence keeps exactly the seventeen-segment path and
// the encoding it had before the field existed: its canonical bytes carry
// no trace of the field and decode, unchanged, under the previous
// contract.
func TestZoneAdmissionLeaseOrdinarySessionUnchanged(t *testing.T) {
	payload := refusalSessionPayload()
	if err := wire.ValidateZoneAdmissionLeasePayload(payload, payload.GetIssuedAtUnixS()); err != nil {
		t.Fatalf("ordinary session refused: %v", err)
	}
	raw, err := wire.MarshalZoneAdmissionLeasePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	previous := dynamicpb.NewMessage(previousPayloadDescriptor(t))
	if err := wire.UnmarshalCanonical(raw, previous, apb.MaxLeasePayloadBytes, "lease payload"); err != nil {
		t.Fatalf("previous contract refused an ordinary session lease: %v", err)
	}
	reencoded, err := wire.MarshalCanonical(previous)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, raw) {
		t.Fatal("an ordinary session lease encodes differently under the previous contract")
	}
}

// TestZoneAdmissionLeaseMicropodProfileRefusedByPreviousContract checks
// that a verifier built before the field existed refuses a Micropod
// session lease outright: field 31 is unknown to it, and a payload with an
// unknown field has no canonical encoding, so its canonical decode fails
// as malformed. Nothing in the previous contract can admit the profile.
func TestZoneAdmissionLeaseMicropodProfileRefusedByPreviousContract(t *testing.T) {
	payload := micropodSessionPayload()
	raw, err := wire.MarshalZoneAdmissionLeasePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	previous := dynamicpb.NewMessage(previousPayloadDescriptor(t))
	if err := wire.UnmarshalCanonical(raw, previous, apb.MaxLeasePayloadBytes, "lease payload"); !errors.Is(err, wire.ErrAdmissionMalformed) {
		t.Fatalf("previous contract: err = %v, want ErrAdmissionMalformed", err)
	}
	if err := wire.RejectUnknown(previous); err == nil {
		t.Fatal("the previous contract decoded the sequence as a known field")
	}
}

// previousPayloadDescriptor is ZoneAdmissionLeasePayload as it was before
// micropod_sequence: the current descriptor with field 31 removed.
func previousPayloadDescriptor(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := protodesc.ToFileDescriptorProto(apb.File_idyl_admission_v3_admission_proto)
	found := false
	for _, message := range file.GetMessageType() {
		if message.GetName() != "ZoneAdmissionLeasePayload" {
			continue
		}
		kept := message.Field[:0]
		for _, field := range message.GetField() {
			if field.GetNumber() == 31 {
				found = true
				continue
			}
			kept = append(kept, field)
		}
		message.Field = kept
	}
	if !found {
		t.Fatal("ZoneAdmissionLeasePayload has no field 31")
	}
	previous, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := previous.Messages().ByName("ZoneAdmissionLeasePayload")
	if descriptor == nil {
		t.Fatal("previous descriptor has no ZoneAdmissionLeasePayload")
	}
	return descriptor
}
