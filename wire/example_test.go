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
	"fmt"
	"log"
	"time"

	"github.com/idyl-labs/hyperplane-go/generation"
	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	"github.com/idyl-labs/hyperplane-go/wire/svidtest"
)

// A control stream carries one length-prefixed protobuf message per frame.
// The receiver names its cap; zero selects DefaultMaxFrame.
func ExampleWriteFrame() {
	var stream bytes.Buffer
	sent := &mpb.DockGen{
		Edge: &mpb.EdgeTag{Incarnation: []byte("edge-a"), LeaseId: []byte("lease-a")},
		Slot: 7, SlotEpoch: 9,
	}
	if err := wire.WriteFrame(&stream, sent); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("prefix % x\n", stream.Bytes()[:4])

	var received mpb.DockGen
	if err := wire.ReadFrame(&stream, &received, 0); err != nil {
		log.Fatal(err)
	}
	fmt.Println(wire.RedactGen(wire.GenFromProtoV2(&received)))

	// A peer cannot make the receiver buffer more than its cap.
	oversized := []byte{0x00, 0x00, 0x01, 0x00} // declares 256 bytes
	_, err := wire.ReadRawFrame(bytes.NewReader(oversized), 128)
	fmt.Println(errors.Is(err, wire.ErrFrameTooLarge))
	// Output:
	// prefix 00 00 00 17
	// edge-a/lease-a#7.9
	// true
}

// A lane stream begins with the kind byte and its attribution header. The
// stream dispatcher consumes the kind byte; ReadLaneHeader reads the rest
// and leaves the payload unread.
func ExampleAppendLaneHeader() {
	stream, err := wire.AppendLaneHeader(nil, wire.LaneStreamHeader{
		LaneID: 300,
		Class:  wire.LaneStreamClassE2EMTLS,
		Header: []byte("route=a"),
	})
	if err != nil {
		log.Fatal(err)
	}
	stream = append(stream, "payload"...)
	fmt.Printf("% x\n", stream[:6])

	r := bytes.NewReader(stream)
	kind, err := r.ReadByte()
	if err != nil || kind != wire.StreamKindLane {
		log.Fatal("not a lane stream")
	}
	h, err := wire.ReadLaneHeader(r)
	if err != nil {
		log.Fatal(err)
	}
	rest := make([]byte, r.Len())
	_, _ = r.Read(rest)
	fmt.Printf("lane %d class %d header %q payload %q\n", h.LaneID, h.Class, h.Header, rest)
	// Output:
	// 03 ac 02 01 00 07
	// lane 300 class 1 header "route=a" payload "payload"
}

// A lane datagram is attributed by two varints; a single zero byte is a
// keepalive that only signals activity.
func ExampleParseLaneDatagram() {
	datagram, err := wire.AppendLaneDatagram(nil, 5, 42, []byte("ping"))
	if err != nil {
		log.Fatal(err)
	}
	dg, keepalive, err := wire.ParseLaneDatagram(datagram)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(dg.LaneID, dg.FlowID, string(dg.Payload), keepalive)

	_, keepalive, err = wire.ParseLaneDatagram(wire.LaneKeepalive())
	fmt.Println(keepalive, err)
	// Output:
	// 5 42 ping false
	// true <nil>
}

// RedactGen is the rendering for logs and errors: it never includes the
// generation's nonce, and binary identifiers are hex-encoded.
func ExampleRedactGen() {
	g := generation.DockGen{
		Edge:  generation.EdgeTag{Incarnation: "\x01\x02", LeaseID: "lease-a"},
		Slot:  3,
		Epoch: 1,
		Nonce: "do-not-log-this",
	}
	fmt.Println(wire.RedactGen(g))
	// Output:
	// 0102/lease-a#3.1
}

// A zone admission signer issues a lease; a verifier parses it at its own
// clock, checks the signer against its local trust bundle, and binds the
// lease to the authenticated peer.
func ExampleParseZoneAdmissionLease() {
	issued := time.Unix(1_700_000_000, 0)
	authority, err := svidtest.NewAuthority("z1.zone.example.com", svidtest.WithClock(func() time.Time { return issued }))
	if err != nil {
		log.Fatal(err)
	}
	signer, err := authority.IssueAdmissionSigner(mpb.Plane_PLANE_CONTROL)
	if err != nil {
		log.Fatal(err)
	}
	payload := &apb.ZoneAdmissionLeasePayload{
		Version:              apb.PayloadVersion,
		LeaseId:              []byte("lease-id-0000001"),
		Zone:                 "z1",
		FabricPlane:          mpb.Plane_PLANE_CONTROL,
		Principal:            "spiffe://z1.zone.example.com/subnet/subnet-a/node/node-a",
		SubjectSpkiSha256:    bytes.Repeat([]byte{0x02}, apb.SHA256Bytes),
		EndpointKind:         mpb.EndpointKind_ENDPOINT_KIND_NODE,
		SubnetId:             "subnet-a",
		OwnerScope:           "node:node-a",
		NodeId:               "node-a",
		NodeAdmission:        apb.NodeAdmission_NODE_ADMISSION_PROVIDER,
		AdapterClasses:       1, // control-dock
		PolicyProfile:        "default",
		PolicyProfileVersion: 1,
		NotBeforeUnixS:       uint64(issued.Unix()),
		IssuedAtUnixS:        uint64(issued.Unix()) + 60,
		NotAfterUnixS:        uint64(issued.Unix()) + 3_600,
	}
	raw, err := signer.SignLease(payload)
	if err != nil {
		log.Fatal(err)
	}

	// The verifier side.
	now := issued.Add(2 * time.Minute)
	envelope, parsed, err := wire.ParseZoneAdmissionLease(raw, uint64(now.Unix()))
	if err != nil {
		log.Fatal(err)
	}
	expectedSigner, err := wire.AdmissionSignerURIForPlane("z1.zone.example.com", mpb.Plane_PLANE_CONTROL)
	if err != nil {
		log.Fatal(err)
	}
	facts, err := wire.VerifyZoneAdmissionLeaseSigner(envelope, authority.Bundle(), expectedSigner, nil, now)
	if err != nil {
		log.Fatal(err)
	}
	err = wire.ValidateZoneAdmissionLeaseBinding(parsed, wire.LeasePeer{
		Principal:           parsed.GetPrincipal(),
		SubjectSPKISHA256:   parsed.GetSubjectSpkiSha256(),
		Zone:                "z1",
		FabricPlane:         mpb.Plane_PLANE_CONTROL,
		EndpointKind:        mpb.EndpointKind_ENDPOINT_KIND_NODE,
		SVIDNotAfterUnixS:   parsed.GetNotAfterUnixS(),
		SignerNotAfterUnixS: facts.NotAfterUnixS,
	})
	fmt.Println("signer:", facts.URI)
	fmt.Println("admitted:", parsed.GetPrincipal(), err == nil)
	fmt.Println("adapters:", wire.AdapterClassesFromBits(parsed.GetAdapterClasses()))

	// The same lease is refused once it expires.
	_, _, err = wire.ParseZoneAdmissionLease(raw, parsed.GetNotAfterUnixS())
	fmt.Println("expired:", errors.Is(err, wire.ErrAdmissionExpired))
	// Output:
	// signer: spiffe://z1.zone.example.com/service/join/admission-issuer
	// admitted: spiffe://z1.zone.example.com/subnet/subnet-a/node/node-a true
	// adapters: [control-dock]
	// expired: true
}
