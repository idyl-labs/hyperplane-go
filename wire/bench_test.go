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
	"crypto/ed25519"
	"io"
	"testing"

	"github.com/idyl-labs/hyperplane-go/wire"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv3"
)

// benchHello is a dock/3 hello of realistic size: a full signed lease and
// proof input.
func benchHello(b *testing.B) *dockpb.DockHello {
	b.Helper()
	lease, _, _ := fixtureLease(b)
	input, err := wire.BuildDockProofInput(lease, 20_000, fuzzPredecessor(), fuzzExporter)
	if err != nil {
		b.Fatal(err)
	}
	_, svidKey := goldenSVIDKey()
	return &dockpb.DockHello{
		Contract: dockpb.Contract, KeepaliveMs: 20_000, PredecessorGen: fuzzPredecessor(),
		LeaseEnvelope: lease, DockProofInput: input,
		DockProofSignature: ed25519.Sign(svidKey, wire.DockProofSignatureInput(input)),
	}
}

func BenchmarkWriteFrame(b *testing.B) {
	hello := benchHello(b)
	var stream bytes.Buffer
	if err := wire.WriteFrame(&stream, hello); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(stream.Len()))
	b.ReportAllocs()
	for b.Loop() {
		if err := wire.WriteFrame(io.Discard, hello); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReadFrame(b *testing.B) {
	var stream bytes.Buffer
	if err := wire.WriteFrame(&stream, benchHello(b)); err != nil {
		b.Fatal(err)
	}
	frame := stream.Bytes()
	r := bytes.NewReader(frame)
	b.SetBytes(int64(len(frame)))
	b.ReportAllocs()
	for b.Loop() {
		r.Reset(frame)
		var hello dockpb.DockHello
		if err := wire.ReadFrame(r, &hello, 0); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAppendLaneHeader(b *testing.B) {
	h := wire.LaneStreamHeader{LaneID: 1 << 40, Class: wire.LaneStreamClassE2EMTLS, Header: []byte("route=a")}
	buf := make([]byte, 0, 64)
	b.ReportAllocs()
	for b.Loop() {
		var err error
		if buf, err = wire.AppendLaneHeader(buf[:0], h); err != nil {
			b.Fatal(err)
		}
	}
	b.SetBytes(int64(len(buf)))
}

func BenchmarkReadLaneHeader(b *testing.B) {
	encoded, err := wire.AppendLaneHeader(nil, wire.LaneStreamHeader{
		LaneID: 1 << 40, Class: wire.LaneStreamClassE2EMTLS, Header: []byte("route=a"),
	})
	if err != nil {
		b.Fatal(err)
	}
	body := encoded[1:]
	r := bytes.NewReader(body)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		r.Reset(body)
		if _, err := wire.ReadLaneHeader(r); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseLaneDatagram(b *testing.B) {
	datagram, err := wire.AppendLaneDatagram(nil, 1<<40, 7, make([]byte, 1200))
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(datagram)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := wire.ParseLaneDatagram(datagram); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseZoneAdmissionLease(b *testing.B) {
	raw, _, _ := fixtureLease(b)
	now := uint64(goldenClock.Unix())
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := wire.ParseZoneAdmissionLease(raw, now); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyZoneAdmissionLease measures the complete admission
// decision for one lease: parse, signer profile, signature, and chain
// verification against the trust bundle.
func BenchmarkVerifyZoneAdmissionLease(b *testing.B) {
	raw, _, authority := fixtureLease(b)
	expectedURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, mpb.Plane_PLANE_DATA)
	if err != nil {
		b.Fatal(err)
	}
	bundle := authority.Bundle()
	now := uint64(goldenClock.Unix())
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		envelope, _, err := wire.ParseZoneAdmissionLease(raw, now)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := wire.VerifyZoneAdmissionLeaseSigner(envelope, bundle, expectedURI, nil, goldenClock); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyDockProof(b *testing.B) {
	hello := benchHello(b)
	public, _ := goldenSVIDKey()
	b.ReportAllocs()
	for b.Loop() {
		if err := wire.VerifyDockProof(hello.DockProofInput, hello.DockProofSignature, public,
			hello.LeaseEnvelope, hello.KeepaliveMs, hello.PredecessorGen, fuzzExporter); err != nil {
			b.Fatal(err)
		}
	}
}
