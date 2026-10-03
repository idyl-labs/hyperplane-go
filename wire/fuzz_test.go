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
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"math/bits"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/generation"
	"github.com/idyl-labs/hyperplane-go/wire"
	apb "github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	mpb "github.com/idyl-labs/hyperplane-go/wire/commonv2"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv3"
	"github.com/idyl-labs/hyperplane-go/wire/internal/conformance"
	"github.com/idyl-labs/hyperplane-go/wire/svidtest"
)

// fixtureLease mints one valid data-plane pod lease, the same lease as
// goldenLease, for callers that hold a testing.TB rather than a *testing.T.
func fixtureLease(tb testing.TB) (raw []byte, signer *svidtest.SignerIdentity, authority *svidtest.Authority) {
	tb.Helper()
	authority, err := svidtest.NewAuthority(goldenTrustDomain, svidtest.WithClock(func() time.Time {
		return time.Unix(1_700_000_000, 0)
	}))
	if err != nil {
		tb.Fatal(err)
	}
	signer, err = authority.IssueAdmissionSigner(mpb.Plane_PLANE_DATA,
		svidtest.WithValidity(time.Unix(1_699_999_000, 0), time.Unix(1_700_050_000, 0)))
	if err != nil {
		tb.Fatal(err)
	}
	raw, err = signer.SignLease(goldenPodPayload())
	if err != nil {
		tb.Fatal(err)
	}
	return raw, signer, authority
}

// corpusVectors loads the committed admission conformance vectors, which
// are real encodings of valid and refused leases.
func corpusVectors(tb testing.TB) []conformance.Vector {
	tb.Helper()
	raw, err := os.ReadFile("testdata/admissionv3-conformance/corpus.json")
	if err != nil {
		tb.Fatal(err)
	}
	var corpus conformance.Corpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		tb.Fatal(err)
	}
	return corpus.Vectors
}

func corpusEnvelope(tb testing.TB, v conformance.Vector) []byte {
	tb.Helper()
	raw, err := hex.DecodeString(v.EnvelopeHex)
	if err != nil {
		tb.Fatal(err)
	}
	return raw
}

// fuzzExporter is a fixed TLS exporter value for dock proof seeds.
var fuzzExporter = bytes.Repeat([]byte{0x44}, apb.TLSExporterBytes)

func fuzzPredecessor() *mpb.DockGen {
	return &mpb.DockGen{
		Edge: &mpb.EdgeTag{Incarnation: []byte("edge-a"), LeaseId: []byte("lease-a")},
		Slot: 7, SlotEpoch: 9, Nonce: []byte("nonce-000001"),
	}
}

// isOneOf reports whether err matches any of the targets under errors.Is.
func isOneOf(err error, targets ...error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

// effectiveFrameCap mirrors the documented cap rule: maxLen <= 0 means
// DefaultMaxFrame.
func effectiveFrameCap(maxLen int) int {
	if maxLen <= 0 {
		return wire.DefaultMaxFrame
	}
	return maxLen
}

// clampFuzzFrameCap keeps a fuzzed cap within twice the default. A caller
// may choose any cap, and the receiver allocates up to it, so an unbounded
// fuzzed cap would only measure the fuzzing machine's memory.
func clampFuzzFrameCap(maxLen int) int {
	if maxLen > 2*wire.DefaultMaxFrame {
		return 2 * wire.DefaultMaxFrame
	}
	return maxLen
}

// FuzzReadRawFrame checks the frame reader against arbitrary streams and
// caps: it refuses with ErrFrameTooLarge exactly when the declared length
// exceeds the effective cap, reports truncation as io.EOF or
// io.ErrUnexpectedEOF, and otherwise returns a body within the cap that
// WriteRawFrame re-encodes to exactly the bytes consumed.
func FuzzReadRawFrame(f *testing.F) {
	var seed bytes.Buffer
	if err := wire.WriteFrame(&seed, frameTestGen()); err != nil {
		f.Fatal(err)
	}
	f.Add(seed.Bytes(), 0)
	f.Add(seed.Bytes(), -1)
	f.Add(seed.Bytes(), 8)
	f.Add(seed.Bytes(), len(seed.Bytes())-4)
	f.Add(append(framePrefix(0), 'x'), 0)
	f.Add(framePrefix(wire.DefaultMaxFrame+1), 0)
	f.Add(framePrefix(0xffffffff), 16)
	f.Add([]byte{0x00, 0x00}, 0)
	f.Add([]byte{}, 0)

	f.Fuzz(func(t *testing.T, data []byte, maxLen int) {
		maxLen = clampFuzzFrameCap(maxLen)
		limit := effectiveFrameCap(maxLen)
		got, err := wire.ReadRawFrame(bytes.NewReader(data), maxLen)
		if len(data) >= 4 && int64(binary.BigEndian.Uint32(data)) > int64(limit) {
			if !errors.Is(err, wire.ErrFrameTooLarge) {
				t.Fatalf("declared length over cap %d: err = %v, want ErrFrameTooLarge", limit, err)
			}
			return
		}
		if err != nil {
			if !isOneOf(err, io.EOF, io.ErrUnexpectedEOF) {
				t.Fatalf("err = %v, want io.EOF or io.ErrUnexpectedEOF", err)
			}
			return
		}
		if len(got) > limit {
			t.Fatalf("returned %d bytes past cap %d", len(got), limit)
		}
		var out bytes.Buffer
		if err := wire.WriteRawFrame(&out, got); err != nil {
			t.Fatalf("re-encoding a read frame: %v", err)
		}
		if !bytes.Equal(out.Bytes(), data[:out.Len()]) {
			t.Fatalf("re-encoded frame %x differs from consumed input %x", out.Bytes(), data[:out.Len()])
		}
	})
}

// FuzzReadFrame checks the message-frame reader: whatever the stream and
// cap, a refusal is the raw frame refusal or a decode error of a frame that
// was read in full, and a success decodes exactly the bytes of one raw
// frame.
func FuzzReadFrame(f *testing.F) {
	lease, _, _ := fixtureLease(f)
	input, err := wire.BuildDockProofInput(lease, 20_000, fuzzPredecessor(), fuzzExporter)
	if err != nil {
		f.Fatal(err)
	}
	var seed bytes.Buffer
	if err := wire.WriteFrame(&seed, &dockpb.DockHello{
		Contract: dockpb.Contract, KeepaliveMs: 20_000, PredecessorGen: fuzzPredecessor(),
		LeaseEnvelope: lease, DockProofInput: input, DockProofSignature: make([]byte, 64),
	}); err != nil {
		f.Fatal(err)
	}
	f.Add(seed.Bytes(), 0)
	f.Add(seed.Bytes(), 64)
	f.Add(append(framePrefix(3), 0x0a, 0x05, 'a'), 0)
	f.Add(append(framePrefix(2), 0x10, 0x01), -1)

	f.Fuzz(func(t *testing.T, data []byte, maxLen int) {
		maxLen = clampFuzzFrameCap(maxLen)
		var got dockpb.DockHello
		err := wire.ReadFrame(bytes.NewReader(data), &got, maxLen)
		raw, rawErr := wire.ReadRawFrame(bytes.NewReader(data), maxLen)
		if rawErr != nil {
			if err == nil || err.Error() != rawErr.Error() {
				t.Fatalf("ReadFrame err = %v, raw frame err = %v", err, rawErr)
			}
			return
		}
		var want dockpb.DockHello
		wantErr := proto.Unmarshal(raw, &want)
		if (err == nil) != (wantErr == nil) {
			t.Fatalf("ReadFrame err = %v, decoding the raw frame err = %v", err, wantErr)
		}
		if err == nil && !proto.Equal(&got, &want) {
			t.Fatal("ReadFrame decoded a different message than its raw frame")
		}
	})
}

// FuzzReadLaneHeader checks the lane attribution reader against arbitrary
// bytes after the kind byte: a refusal is ErrLaneAttribution or a
// truncation (io.EOF only before the first byte), and a success re-encodes
// with AppendLaneHeader to the kind byte followed by exactly the bytes
// consumed, with the header within its u16 bound.
func FuzzReadLaneHeader(f *testing.F) {
	for _, h := range []wire.LaneStreamHeader{
		{LaneID: 1, Class: wire.LaneStreamClassE2EMTLS},
		{LaneID: 300, Class: wire.LaneStreamClassPassthrough, Header: []byte("route=a")},
		{LaneID: math.MaxUint64, Class: wire.LaneStreamClassE2EMTLS, Header: bytes.Repeat([]byte{0xab}, 300)},
	} {
		b, err := wire.AppendLaneHeader(nil, h)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b[1:])
		f.Add(append(b[1:], "payload"...))
	}
	f.Add([]byte{0x80, 0x00})
	f.Add([]byte{0x00, 0x01, 0x00, 0x00})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02})
	f.Add([]byte{0x01, 0x07, 0x00, 0x00})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		h, err := wire.ReadLaneHeader(r)
		if err != nil {
			switch {
			case errors.Is(err, wire.ErrLaneAttribution), errors.Is(err, io.ErrUnexpectedEOF):
			case errors.Is(err, io.EOF):
				if len(data) != 0 {
					t.Fatalf("clean io.EOF after %d bytes of a header", len(data))
				}
			default:
				t.Fatalf("err = %v, want ErrLaneAttribution or a truncation", err)
			}
			return
		}
		consumed := len(data) - r.Len()
		if h.LaneID == 0 || len(h.Header) > wire.LaneHeaderMaxLen {
			t.Fatalf("accepted header outside its grammar: %+v", h)
		}
		encoded, err := wire.AppendLaneHeader(nil, h)
		if err != nil {
			t.Fatalf("re-encoding an accepted header: %v", err)
		}
		if encoded[0] != wire.StreamKindLane || !bytes.Equal(encoded[1:], data[:consumed]) {
			t.Fatalf("re-encoded %x, consumed %x", encoded, data[:consumed])
		}
	})
}

// FuzzParseLaneDatagram checks the datagram parser: a refusal is
// ErrLaneAttribution, a keepalive is exactly a leading minimal zero varint,
// and any other success re-encodes with AppendLaneDatagram to the exact
// input bytes, with Payload aliasing the tail of the input.
func FuzzParseLaneDatagram(f *testing.F) {
	for _, dg := range []wire.LaneDatagram{
		{LaneID: 1, FlowID: 0},
		{LaneID: 300, FlowID: 7, Payload: []byte("flow bytes")},
		{LaneID: math.MaxUint64, FlowID: math.MaxUint64, Payload: []byte{0x00}},
	} {
		b, err := wire.AppendLaneDatagram(nil, dg.LaneID, dg.FlowID, dg.Payload)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add(wire.LaneKeepalive())
	f.Add([]byte{0x00, 0xff})
	f.Add([]byte{0x80, 0x00})
	f.Add([]byte{0x01})
	f.Add([]byte{0x01, 0x80})
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		dg, keepalive, err := wire.ParseLaneDatagram(data)
		if err != nil {
			if !errors.Is(err, wire.ErrLaneAttribution) {
				t.Fatalf("err = %v, want ErrLaneAttribution", err)
			}
			if keepalive {
				t.Fatal("refusal reported as keepalive")
			}
			return
		}
		if keepalive {
			if data[0] != 0x00 || dg.LaneID != 0 || dg.Payload != nil {
				t.Fatalf("keepalive from %x parsed as %+v", data, dg)
			}
			return
		}
		if dg.LaneID == 0 {
			t.Fatal("attributed datagram with lane_id 0")
		}
		encoded, err := wire.AppendLaneDatagram(nil, dg.LaneID, dg.FlowID, dg.Payload)
		if err != nil {
			t.Fatalf("re-encoding an accepted datagram: %v", err)
		}
		if !bytes.Equal(encoded, data) {
			t.Fatalf("re-encoded %x, input %x", encoded, data)
		}
		if len(dg.Payload) > 0 && &dg.Payload[0] != &data[len(data)-len(dg.Payload)] {
			t.Fatal("payload does not alias the input")
		}
	})
}

// FuzzParseZoneAdmissionLease checks the lease parser against arbitrary
// envelopes and clocks, seeded with every conformance vector. A refusal
// carries an admission refusal class. An accepted lease re-marshals to the
// exact input, its payload re-marshals to the exact signed payload bytes,
// and the structural signer judgment either refuses with a signer or
// signature class or returns facts that match the envelope.
func FuzzParseZoneAdmissionLease(f *testing.F) {
	for _, v := range corpusVectors(f) {
		f.Add(corpusEnvelope(f, v), v.NowUnixS)
	}
	raw, _, _ := fixtureLease(f)
	f.Add(raw, uint64(goldenClock.Unix()))

	f.Fuzz(func(t *testing.T, raw []byte, now uint64) {
		envelope, payload, err := wire.ParseZoneAdmissionLease(raw, now)
		if err != nil {
			if !isOneOf(err, wire.ErrAdmissionMalformed, wire.ErrAdmissionNonCanonical, wire.ErrAdmissionExpired,
				wire.ErrAdmissionNotYetValid, wire.ErrAdmissionUnsupportedContract) {
				t.Fatalf("err = %v, want an admission refusal class", err)
			}
			if envelope != nil || payload != nil {
				t.Fatal("refusal returned a lease")
			}
			return
		}
		if len(raw) > apb.MaxLeaseEnvelopeBytes {
			t.Fatalf("accepted a %d-byte envelope", len(raw))
		}
		remarshaled, err := wire.MarshalZoneAdmissionLease(envelope)
		if err != nil {
			t.Fatalf("re-marshaling an accepted lease: %v", err)
		}
		if !bytes.Equal(remarshaled, raw) {
			t.Fatal("accepted lease does not re-marshal to its input")
		}
		payloadBytes, err := wire.MarshalZoneAdmissionLeasePayload(payload)
		if err != nil {
			t.Fatalf("re-marshaling an accepted payload: %v", err)
		}
		if !bytes.Equal(payloadBytes, envelope.GetPayload()) {
			t.Fatal("accepted payload does not re-marshal to the signed bytes")
		}
		if now < payload.GetNotBeforeUnixS() || now >= payload.GetNotAfterUnixS() {
			t.Fatalf("accepted lease outside its validity at %d", now)
		}

		expectedURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, payload.GetFabricPlane())
		if err != nil {
			t.Fatalf("accepted payload names plane %v", payload.GetFabricPlane())
		}
		facts, err := wire.ValidateZoneAdmissionLeaseSigner(envelope, expectedURI, time.Unix(int64(min(now, math.MaxInt64)), 0))
		if err != nil {
			if !isOneOf(err, wire.ErrAdmissionSignerProfile, wire.ErrAdmissionSignerValidity, wire.ErrAdmissionSignature,
				wire.ErrAdmissionLeaseOutsideSigner) {
				t.Fatalf("signer err = %v, want a signer or signature class", err)
			}
			return
		}
		if facts.URI != expectedURI || !bytes.Equal(facts.KeyID, envelope.GetSignerKeyId()) {
			t.Fatal("signer facts do not match the envelope")
		}
	})
}

// FuzzParseDockProofInput checks that the proof input parser accepts only
// the unique canonical encoding of an in-profile input: a refusal is
// ErrAdmissionMalformed or ErrAdmissionNonCanonical, and an accepted input
// re-encodes canonically to the exact bytes.
func FuzzParseDockProofInput(f *testing.F) {
	lease, _, _ := fixtureLease(f)
	for _, pred := range []*mpb.DockGen{nil, fuzzPredecessor()} {
		input, err := wire.BuildDockProofInput(lease, 20_000, pred, fuzzExporter)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(input)
		f.Add(append(append([]byte(nil), input...), 0x08, 0x01))
	}
	parity, err := hex.DecodeString(goldenParityDockProofHex)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(parity)

	f.Fuzz(func(t *testing.T, raw []byte) {
		input, err := wire.ParseDockProofInput(raw)
		if err != nil {
			if !isOneOf(err, wire.ErrAdmissionMalformed, wire.ErrAdmissionNonCanonical) {
				t.Fatalf("err = %v, want ErrAdmissionMalformed or ErrAdmissionNonCanonical", err)
			}
			return
		}
		if len(raw) > apb.MaxDockProofInputBytes {
			t.Fatalf("accepted a %d-byte proof input", len(raw))
		}
		encoded, err := wire.MarshalCanonical(input)
		if err != nil {
			t.Fatalf("re-encoding an accepted input: %v", err)
		}
		if !bytes.Equal(encoded, raw) {
			t.Fatal("accepted proof input is not its own canonical encoding")
		}
	})
}

// FuzzParseLeaseSignature checks the strict signature parser: a refusal is
// ErrLeaseSignatureEncoding, and an accepted signature is the unique
// canonical encoding of its in-range low-S scalars, so it re-encodes to the
// exact input and normalization leaves it unchanged.
func FuzzParseLeaseSignature(f *testing.F) {
	lowS, err := wire.EncodeLeaseSignature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(lowS)
	high := rawSequence(rawInteger(0x05), rawInteger(paddedIntBytes(new(big.Int).Sub(p256Order(), big.NewInt(7)))...))
	f.Add(high)
	for _, v := range corpusVectors(f) {
		var envelope apb.ZoneAdmissionLease
		if proto.Unmarshal(corpusEnvelope(f, v), &envelope) == nil && len(envelope.GetSignature()) > 0 {
			f.Add(envelope.GetSignature())
		}
	}

	f.Fuzz(func(t *testing.T, der []byte) {
		r, s, err := wire.ParseLeaseSignature(der)
		if err != nil {
			if !errors.Is(err, wire.ErrLeaseSignatureEncoding) {
				t.Fatalf("err = %v, want ErrLeaseSignatureEncoding", err)
			}
			return
		}
		if s.Cmp(p256HalfOrder()) > 0 || r.Sign() <= 0 || r.Cmp(p256Order()) >= 0 {
			t.Fatalf("accepted out-of-profile scalars r=%v s=%v", r, s)
		}
		encoded, err := wire.EncodeLeaseSignature(r, s)
		if err != nil {
			t.Fatalf("re-encoding accepted scalars: %v", err)
		}
		if !bytes.Equal(encoded, der) {
			t.Fatalf("re-encoded %x, input %x", encoded, der)
		}
		normalized, err := wire.NormalizeLeaseSignatureLowS(der)
		if err != nil || !bytes.Equal(normalized, der) {
			t.Fatalf("normalizing a canonical signature gave %x, %v", normalized, err)
		}
	})
}

// FuzzNormalizeLeaseSignatureLowS checks producer normalization: a refusal
// is ErrLeaseSignatureEncoding, and an accepted signature becomes the
// canonical encoding with the same r and either the same s or its low-S
// twin, and normalizing again changes nothing.
func FuzzNormalizeLeaseSignatureLowS(f *testing.F) {
	lowS, err := wire.EncodeLeaseSignature(big.NewInt(5), big.NewInt(7))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(lowS)
	f.Add(rawSequence(rawInteger(0x05), rawInteger(paddedIntBytes(new(big.Int).Sub(p256Order(), big.NewInt(7)))...)))
	f.Add(rawSequence(rawInteger(0x01), rawInteger(0x00, 0x01)))

	f.Fuzz(func(t *testing.T, der []byte) {
		normalized, err := wire.NormalizeLeaseSignatureLowS(der)
		if err != nil {
			if !errors.Is(err, wire.ErrLeaseSignatureEncoding) {
				t.Fatalf("err = %v, want ErrLeaseSignatureEncoding", err)
			}
			return
		}
		r, s, err := wire.ParseLeaseSignature(normalized)
		if err != nil {
			t.Fatalf("normalized signature is not canonical: %v", err)
		}
		again, err := wire.NormalizeLeaseSignatureLowS(normalized)
		if err != nil || !bytes.Equal(again, normalized) {
			t.Fatal("normalization is not idempotent")
		}
		// The input differs from the output only in s, so swapping the
		// twin back must reproduce it when the input was high-S.
		if _, _, strictErr := wire.ParseLeaseSignature(der); strictErr == nil {
			if !bytes.Equal(normalized, der) {
				t.Fatal("normalization changed a canonical signature")
			}
			return
		}
		twin := new(big.Int).Sub(p256Order(), s)
		highForm := rawSequence(rawInteger(paddedIntBytes(r)...), rawInteger(paddedIntBytes(twin)...))
		if !bytes.Equal(highForm, der) {
			t.Fatalf("normalized %x is not the low-S twin of %x", normalized, der)
		}
	})
}

// FuzzValidateDockHelloV3 checks the dock/3 opening check against arbitrary
// hello encodings: every refusal carries a malformed, non-canonical or
// binding class, and an accepted hello carries a canonical proof input
// bound to the hello's lease digest, keepalive and predecessor.
func FuzzValidateDockHelloV3(f *testing.F) {
	lease, _, _ := fixtureLease(f)
	_, svidKey := goldenSVIDKey()
	for _, pred := range []*mpb.DockGen{nil, fuzzPredecessor()} {
		input, err := wire.BuildDockProofInput(lease, 20_000, pred, fuzzExporter)
		if err != nil {
			f.Fatal(err)
		}
		hello := &dockpb.DockHello{
			Contract: dockpb.Contract, KeepaliveMs: 20_000, PredecessorGen: pred,
			LeaseEnvelope: lease, DockProofInput: input,
			DockProofSignature: ed25519.Sign(svidKey, wire.DockProofSignatureInput(input)),
		}
		raw, err := proto.Marshal(hello)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		var hello dockpb.DockHello
		if err := proto.Unmarshal(raw, &hello); err != nil {
			return
		}
		if err := wire.ValidateDockHelloV3(&hello); err != nil {
			if !isOneOf(err, wire.ErrAdmissionMalformed, wire.ErrAdmissionNonCanonical, wire.ErrAdmissionBinding) {
				t.Fatalf("err = %v, want a malformed, non-canonical or binding class", err)
			}
			return
		}
		input, err := wire.ParseDockProofInput(hello.GetDockProofInput())
		if err != nil {
			t.Fatalf("accepted hello carries an unparseable proof input: %v", err)
		}
		digest := sha256.Sum256(hello.GetLeaseEnvelope())
		if !bytes.Equal(input.GetLeaseEnvelopeSha256(), digest[:]) || input.GetKeepaliveMs() != hello.GetKeepaliveMs() ||
			!proto.Equal(input.GetPredecessorGen(), hello.GetPredecessorGen()) || hello.GetContract() != dockpb.Contract {
			t.Fatal("accepted hello is not bound to its proof input")
		}
	})
}

// FuzzValidateAdmissionSignerChainDER checks the signer chain validator
// against arbitrary one- and two-certificate chains, seeded with every
// conformance chain: a refusal is ErrAdmissionSignerProfile, and accepted
// facts describe exactly the presented leaf.
func FuzzValidateAdmissionSignerChainDER(f *testing.F) {
	for _, v := range corpusVectors(f) {
		var envelope apb.ZoneAdmissionLease
		if proto.Unmarshal(corpusEnvelope(f, v), &envelope) != nil || len(envelope.GetSignerCertChain()) == 0 {
			continue
		}
		chain := envelope.GetSignerCertChain()
		if len(chain) > 1 {
			f.Add(chain[0], chain[1], true)
		} else {
			f.Add(chain[0], []byte(nil), false)
		}
	}

	f.Fuzz(func(t *testing.T, leaf, intermediate []byte, withIntermediate bool) {
		chain := [][]byte{leaf}
		if withIntermediate {
			chain = append(chain, intermediate)
		}
		for _, plane := range []mpb.Plane{mpb.Plane_PLANE_CONTROL, mpb.Plane_PLANE_DATA} {
			expectedURI, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, plane)
			if err != nil {
				t.Fatal(err)
			}
			facts, err := wire.ValidateAdmissionSignerChainDER(chain, expectedURI)
			if err != nil {
				if !errors.Is(err, wire.ErrAdmissionSignerProfile) {
					t.Fatalf("err = %v, want ErrAdmissionSignerProfile", err)
				}
				continue
			}
			keyID := sha256.Sum256(facts.Leaf.RawSubjectPublicKeyInfo)
			if facts.URI != expectedURI || !bytes.Equal(facts.Leaf.Raw, leaf) || len(facts.Chain) != len(chain) ||
				!bytes.Equal(facts.KeyID, keyID[:]) || facts.PublicKey == nil || facts.NotAfterUnixS <= facts.NotBeforeUnixS {
				t.Fatalf("facts do not describe the presented leaf: %+v", facts)
			}
		}
	})
}

// FuzzValidateExpectedAdmissionSignerURI checks that only canonical signer
// identities are accepted: an accepted URI names the control or data plane
// and is exactly the URI AdmissionSignerURIForPlane derives for its trust
// domain, and a refusal reports the unspecified plane.
func FuzzValidateExpectedAdmissionSignerURI(f *testing.F) {
	for _, plane := range []mpb.Plane{mpb.Plane_PLANE_CONTROL, mpb.Plane_PLANE_DATA} {
		uri, err := wire.AdmissionSignerURIForPlane(goldenTrustDomain, plane)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(uri)
		f.Add(uri + "?")
	}
	f.Add("spiffe://example.com/service/controller/other")
	f.Add("spiffe://user@example.com:1/service/controller/admission-issuer#f")

	f.Fuzz(func(t *testing.T, uri string) {
		plane, err := wire.ValidateExpectedAdmissionSignerURI(uri)
		if err != nil {
			if plane != mpb.Plane_PLANE_UNSPECIFIED {
				t.Fatalf("refusal returned plane %v", plane)
			}
			return
		}
		if plane != mpb.Plane_PLANE_CONTROL && plane != mpb.Plane_PLANE_DATA {
			t.Fatalf("accepted URI names plane %v", plane)
		}
		u, err := url.Parse(uri)
		if err != nil {
			t.Fatalf("accepted URI does not parse: %v", err)
		}
		derived, err := wire.AdmissionSignerURIForPlane(u.Host, plane)
		if err != nil || derived != uri {
			t.Fatalf("accepted %q, but its trust domain derives %q, %v", uri, derived, err)
		}
	})
}

// FuzzAdapterClassesBits checks the adapter class codec: every mask
// renders to one name per set bit and parses back to the same mask, and a
// list of names either is refused with a zero mask or yields a mask whose
// rendering parses back to it.
func FuzzAdapterClassesBits(f *testing.F) {
	f.Add(uint64(0), "")
	f.Add(uint64(0x7f), wire.AdapterStream+","+wire.AdapterFlow)
	f.Add(uint64(1)<<63|1, "adapter(7),adapter(63)")
	f.Add(uint64(4), "adapter(07),stream")

	f.Fuzz(func(t *testing.T, mask uint64, list string) {
		names := wire.AdapterClassesFromBits(mask)
		if len(names) != bits.OnesCount64(mask) {
			t.Fatalf("mask %#x rendered %d names", mask, len(names))
		}
		back, err := wire.AdapterClassesToBits(names)
		if err != nil || back != mask {
			t.Fatalf("mask %#x round-tripped to %#x, %v", mask, back, err)
		}

		parsed, err := wire.AdapterClassesToBits(strings.Split(list, ","))
		if err != nil {
			if parsed != 0 {
				t.Fatalf("refusal returned mask %#x", parsed)
			}
			return
		}
		again, err := wire.AdapterClassesToBits(wire.AdapterClassesFromBits(parsed))
		if err != nil || again != parsed {
			t.Fatalf("parsed mask %#x round-tripped to %#x, %v", parsed, again, err)
		}
	})
}

// FuzzGenFromProtoV2RedactGen checks the generation codec on arbitrary
// wire encodings: the in-memory form carries every wire field byte for
// byte and converts back to the same fields, and RedactGen is a printable
// ASCII rendering that does not depend on the nonce, so the nonce can
// never reach it.
func FuzzGenFromProtoV2RedactGen(f *testing.F) {
	for _, g := range []*mpb.DockGen{
		fuzzPredecessor(),
		{Edge: &mpb.EdgeTag{Incarnation: []byte{0x00, 0xff}, LeaseId: []byte("é")}, Slot: math.MaxUint32, SlotEpoch: 1, Nonce: []byte("edge-a")},
		{},
	} {
		raw, err := proto.Marshal(g)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}

	f.Fuzz(func(t *testing.T, raw []byte) {
		var p mpb.DockGen
		if err := proto.Unmarshal(raw, &p); err != nil {
			return
		}
		g := wire.GenFromProtoV2(&p)
		if g.Edge != wire.TagFromProtoV2(p.GetEdge()) || g.Slot != uint64(p.GetSlot()) ||
			g.Epoch != uint64(p.GetSlotEpoch()) || g.Nonce != string(p.GetNonce()) {
			t.Fatalf("in-memory form %+v does not carry the wire fields", g)
		}
		back, err := wire.GenToProtoV2(g)
		if err != nil {
			t.Fatalf("a wire generation does not convert back: %v", err)
		}
		if !bytes.Equal(back.GetEdge().GetIncarnation(), p.GetEdge().GetIncarnation()) ||
			!bytes.Equal(back.GetEdge().GetLeaseId(), p.GetEdge().GetLeaseId()) ||
			back.GetSlot() != p.GetSlot() || back.GetSlotEpoch() != p.GetSlotEpoch() ||
			!bytes.Equal(back.GetNonce(), p.GetNonce()) {
			t.Fatal("generation round trip changed a wire field")
		}

		rendered := wire.RedactGen(g)
		withoutNonce := g
		withoutNonce.Nonce = ""
		if rendered != wire.RedactGen(withoutNonce) {
			t.Fatal("RedactGen output depends on the nonce")
		}
		for i := 0; i < len(rendered); i++ {
			if rendered[i] < 0x20 || rendered[i] > 0x7e {
				t.Fatalf("RedactGen output %q carries a non-printable byte", rendered)
			}
		}
		if g == (generation.DockGen{}) && rendered != "/#0.0" {
			t.Fatalf("zero generation renders %q", rendered)
		}
	})
}
