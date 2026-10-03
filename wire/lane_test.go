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
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"testing"
)

// These tests check the lane attribution codec against its wire grammar:
// kind byte, minimal-form unsigned LEB128 lane_id, u8 stream class, u16
// big-endian hdr_len, then hdr. Expected bytes are derived from that
// grammar, never from the encoder under test.

// TestLanePinValues fixes the wire values of the lane stream kind byte,
// the draining refusal code, the lane class bits and the stream security
// classes. Each is a wire-format constant shared with every peer, so a
// renumbering must fail here rather than land silently.
func TestLanePinValues(t *testing.T) {
	if StreamKindLane != 0x03 {
		t.Errorf("StreamKindLane = %#x, want 0x03", StreamKindLane)
	}
	if LaneCodeDraining != 0x20 {
		t.Errorf("LaneCodeDraining = %#x, want 0x20", LaneCodeDraining)
	}
	if LaneClassStream != 1<<2 || LaneClassFlow != 1<<3 ||
		LaneClassIngressTarget != 1<<4 || LaneClassSpliceLeg != 1<<5 {
		t.Errorf("lane class bits = %#x/%#x/%#x/%#x, want bits 2 to 5",
			LaneClassStream, LaneClassFlow, LaneClassIngressTarget, LaneClassSpliceLeg)
	}
	if LaneStreamClassE2EMTLS != 0x01 || LaneStreamClassPassthrough != 0x02 {
		t.Errorf("stream classes = %#x/%#x, want 0x01/0x02",
			LaneStreamClassE2EMTLS, LaneStreamClassPassthrough)
	}
}

// TestAppendLaneHeaderVectors checks encoder output byte for byte against
// vectors computed from the attribution grammar, including the minimal-form
// varint requirement at both extremes of the lane_id space.
func TestAppendLaneHeaderVectors(t *testing.T) {
	cases := []struct {
		name string
		h    LaneStreamHeader
		want []byte
	}{
		{
			name: "one-byte varint, e2e-mtls, header bytes",
			h:    LaneStreamHeader{LaneID: 1, Class: LaneStreamClassE2EMTLS, Header: []byte("ab")},
			want: []byte{0x03, 0x01, 0x01, 0x00, 0x02, 'a', 'b'},
		},
		{
			name: "multi-byte varint 300, passthrough, empty header",
			// LEB128(300) = 0xAC 0x02 (300 = 0b100101100 → 0101100|0000010).
			h:    LaneStreamHeader{LaneID: 300, Class: LaneStreamClassPassthrough},
			want: []byte{0x03, 0xAC, 0x02, 0x02, 0x00, 0x00},
		},
		{
			name: "max u64 takes the full 10-byte varint",
			// LEB128(2^64-1) = 0xFF ×9 then 0x01.
			h:    LaneStreamHeader{LaneID: ^uint64(0), Class: LaneStreamClassE2EMTLS},
			want: append([]byte{0x03}, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x01, 0x00, 0x00),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AppendLaneHeader(nil, tc.h)
			if err != nil {
				t.Fatalf("AppendLaneHeader: %v", err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("encoded % x, want % x", got, tc.want)
			}
		})
	}
}

// TestAppendLaneHeaderRefusals checks that values with no legal wire form
// are refused locally rather than sent: lane_id 0, stream class 0x00 or an
// unassigned class, and a header past the u16 bound. The bound itself is
// legal: a 65535-byte header encodes.
func TestAppendLaneHeaderRefusals(t *testing.T) {
	bad := []struct {
		name string
		h    LaneStreamHeader
	}{
		{"lane_id zero", LaneStreamHeader{LaneID: 0, Class: LaneStreamClassE2EMTLS}},
		{"class zero", LaneStreamHeader{LaneID: 1, Class: 0x00}},
		{"class unassigned", LaneStreamHeader{LaneID: 1, Class: 0x07}},
		{"header over u16 bound", LaneStreamHeader{LaneID: 1, Class: LaneStreamClassE2EMTLS, Header: make([]byte, LaneHeaderMaxLen+1)}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := AppendLaneHeader(nil, tc.h); err == nil {
				t.Fatal("AppendLaneHeader accepted a value with no legal wire form")
			}
		})
	}
	// Positive control, same call shape: the u16 bound itself is legal.
	got, err := AppendLaneHeader(nil, LaneStreamHeader{
		LaneID: 1, Class: LaneStreamClassE2EMTLS, Header: make([]byte, LaneHeaderMaxLen),
	})
	if err != nil {
		t.Fatalf("AppendLaneHeader at the u16 bound: %v", err)
	}
	// kind + varint(1) + class + hdr_len 0xFF 0xFF + hdr.
	if want := 1 + 1 + 1 + 2 + LaneHeaderMaxLen; len(got) != want {
		t.Fatalf("encoded %d bytes, want %d", len(got), want)
	}
}

// TestLaneHeaderRoundTrip checks that decode(encode(h)) is the identity,
// that the opaque header bytes pass through verbatim (the fabric parses
// nothing inside hdr), and that the decoder consumes no byte past the
// header, so the caller owns the stream from the first payload byte.
func TestLaneHeaderRoundTrip(t *testing.T) {
	h := LaneStreamHeader{LaneID: 1 << 40, Class: LaneStreamClassPassthrough, Header: []byte{0x00, 0x03, 0xFF, 'x'}}
	enc, err := AppendLaneHeader(nil, h)
	if err != nil {
		t.Fatalf("AppendLaneHeader: %v", err)
	}
	payload := []byte("first payload bytes")
	r := bytes.NewReader(append(enc[1:], payload...)) // kind byte consumed by dispatch
	got, err := ReadLaneHeader(r)
	if err != nil {
		t.Fatalf("ReadLaneHeader: %v", err)
	}
	if got.LaneID != h.LaneID || got.Class != h.Class || !bytes.Equal(got.Header, h.Header) {
		t.Fatalf("round trip: got %+v, want %+v", got, h)
	}
	rest, _ := io.ReadAll(r)
	if !bytes.Equal(rest, payload) {
		t.Fatalf("decoder consumed past the header: %d payload bytes left, want %d", len(rest), len(payload))
	}
}

// TestReadLaneHeaderRejectsOverlongVarint checks the minimal-form rule:
// one lane_id has exactly one wire form, and decoders reject over-long or
// out-of-range encodings. Positive control: the minimal form of the same
// value, in the same call shape, decodes.
func TestReadLaneHeaderRejectsOverlongVarint(t *testing.T) {
	tail := []byte{0x01, 0x00, 0x00} // class e2e-mtls, hdr_len 0
	overlong := [][]byte{
		append([]byte{0x81, 0x00}, tail...),                                                       // 1 in two bytes
		append([]byte{0xFF, 0xFF, 0x00}, tail...),                                                 // 16383 in three bytes (fits two)
		append([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01}, tail...), // 11 bytes
		append([]byte{0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02}, tail...),       // u64 overflow in byte 10
	}
	for i, in := range overlong {
		if _, err := ReadLaneHeader(bytes.NewReader(in)); !errors.Is(err, ErrLaneAttribution) {
			t.Errorf("case %d: over-long/over-range varint decoded, err = %v, want ErrLaneAttribution", i, err)
		}
	}
	// Positive control: minimal form of 1, same tail.
	got, err := ReadLaneHeader(bytes.NewReader(append([]byte{0x01}, tail...)))
	if err != nil || got.LaneID != 1 {
		t.Fatalf("minimal form: got %+v, %v", got, err)
	}
}

// TestReadLaneHeaderRejectsLaneIDZero checks that lane_id 0 is invalid in
// stream attribution. The zero varint is reserved for the datagram
// keepalive form and never names a lane. Positive control: lane_id 1, same
// tail.
func TestReadLaneHeaderRejectsLaneIDZero(t *testing.T) {
	tail := []byte{0x02, 0x00, 0x00}
	if _, err := ReadLaneHeader(bytes.NewReader(append([]byte{0x00}, tail...))); !errors.Is(err, ErrLaneAttribution) {
		t.Fatalf("lane_id 0 decoded, err = %v, want ErrLaneAttribution", err)
	}
	if got, err := ReadLaneHeader(bytes.NewReader(append([]byte{0x01}, tail...))); err != nil || got.LaneID != 1 {
		t.Fatalf("lane_id 1: got %+v, %v", got, err)
	}
}

// TestReadLaneHeaderRejectsStreamClass checks that stream class 0x00 and
// unassigned classes are invalid, while both assigned classes decode in
// the same shape.
func TestReadLaneHeaderRejectsStreamClass(t *testing.T) {
	for _, class := range []byte{0x00, 0x03, 0x07, 0xFF} {
		in := []byte{0x01, class, 0x00, 0x00}
		if _, err := ReadLaneHeader(bytes.NewReader(in)); !errors.Is(err, ErrLaneAttribution) {
			t.Errorf("class %#x decoded, err = %v, want ErrLaneAttribution", class, err)
		}
	}
	for _, class := range []byte{LaneStreamClassE2EMTLS, LaneStreamClassPassthrough} {
		in := []byte{0x01, class, 0x00, 0x00}
		if got, err := ReadLaneHeader(bytes.NewReader(in)); err != nil || got.Class != class {
			t.Errorf("class %#x: got %+v, %v", class, got, err)
		}
	}
}

// TestReadLaneHeaderTruncation checks that a header ending early (inside
// the varint, before the class, inside hdr_len, or with fewer than hdr_len
// header bytes) is an error, never a partial decode. Positive control: the
// complete header from the same grammar decodes.
func TestReadLaneHeaderTruncation(t *testing.T) {
	full := []byte{0xAC, 0x02, 0x01, 0x00, 0x02, 'a', 'b'} // lane 300, e2e-mtls, hdr "ab"
	for cut := 0; cut < len(full); cut++ {
		if _, err := ReadLaneHeader(bytes.NewReader(full[:cut])); err == nil {
			t.Errorf("truncation at %d bytes decoded", cut)
		}
	}
	if got, err := ReadLaneHeader(bytes.NewReader(full)); err != nil ||
		got.LaneID != 300 || got.Class != LaneStreamClassE2EMTLS || !bytes.Equal(got.Header, []byte("ab")) {
		t.Fatalf("complete header: got %+v, %v", got, err)
	}
}

// Datagram attribution.

// TestLaneDatagramRoundTrip checks the datagram wire form: two
// minimal-form LEB128 varints (lane_id, flow_id) followed by the raw
// payload. Expected bytes come from the standard library's LEB128 encoder
// and a hand-built literal, never from this package's decoder alone, so
// the encoder and decoder cannot agree on a shared mistake.
func TestLaneDatagramRoundTrip(t *testing.T) {
	laneIDs := []uint64{1, 2, 127, 128, 300, 16383, 16384, 1 << 32, math.MaxUint64}
	flowIDs := []uint64{0, 1, 127, 128, 300, 1 << 40, math.MaxUint64}
	for _, laneID := range laneIDs {
		for _, flowID := range flowIDs {
			payload := []byte("payload")
			b, err := AppendLaneDatagram(nil, laneID, flowID, payload)
			if err != nil {
				t.Fatalf("AppendLaneDatagram(%d, %d): %v", laneID, flowID, err)
			}
			want := binary.AppendUvarint(binary.AppendUvarint(nil, laneID), flowID)
			want = append(want, payload...)
			if !bytes.Equal(b, want) {
				t.Fatalf("AppendLaneDatagram(%d, %d) = %x, want %x", laneID, flowID, b, want)
			}
			dg, keepalive, err := ParseLaneDatagram(b)
			if err != nil || keepalive {
				t.Fatalf("ParseLaneDatagram(%d, %d): keepalive=%v err=%v", laneID, flowID, keepalive, err)
			}
			if dg.LaneID != laneID || dg.FlowID != flowID || !bytes.Equal(dg.Payload, payload) {
				t.Fatalf("ParseLaneDatagram(%d, %d) = %+v", laneID, flowID, dg)
			}
		}
	}

	// Hand-built literal (lane_id 7 | flow_id 300 | "x"), independent of
	// the encoder.
	dg, keepalive, err := ParseLaneDatagram([]byte{0x07, 0xAC, 0x02, 'x'})
	if err != nil || keepalive {
		t.Fatalf("literal parse: keepalive=%v err=%v", keepalive, err)
	}
	if dg.LaneID != 7 || dg.FlowID != 300 || !bytes.Equal(dg.Payload, []byte("x")) {
		t.Fatalf("literal parse = %+v, want lane 7 flow 300 payload \"x\"", dg)
	}

	// An empty payload is a legal flow datagram: the prefix is the whole
	// wire form.
	dg, keepalive, err = ParseLaneDatagram([]byte{0x07, 0x01})
	if err != nil || keepalive || dg.LaneID != 7 || dg.FlowID != 1 || len(dg.Payload) != 0 {
		t.Fatalf("empty-payload parse = %+v keepalive=%v err=%v", dg, keepalive, err)
	}
}

// TestLaneDatagramKeepaliveForm checks that a leading zero varint is the
// keepalive (transport activity) form: it is drained and never parsed
// further, so trailing bytes are ignored rather than treated as grammar.
// The canonical keepalive is the single byte 0x00.
func TestLaneDatagramKeepaliveForm(t *testing.T) {
	if got := LaneKeepalive(); !bytes.Equal(got, []byte{0x00}) {
		t.Fatalf("LaneKeepalive() = %x, want the canonical single byte 0x00", got)
	}
	for _, b := range [][]byte{{0x00}, {0x00, 0xFF, 0x07, 0x00}} {
		_, keepalive, err := ParseLaneDatagram(b)
		if err != nil || !keepalive {
			t.Fatalf("ParseLaneDatagram(%x): keepalive=%v err=%v, want it read as a lane keepalive", b, keepalive, err)
		}
	}
}

// TestLaneDatagramViolations checks that malformed attribution returns
// ErrLaneAttribution, so the caller can apply the receiver's answer to a
// bad datagram, which is a silent drop. Minimal form is required for both
// varints, so a non-minimal encoding of zero is a violation, not a
// keepalive.
func TestLaneDatagramViolations(t *testing.T) {
	if _, err := AppendLaneDatagram(nil, 0, 1, nil); !errors.Is(err, ErrLaneAttribution) {
		t.Fatalf("AppendLaneDatagram(lane_id 0) err = %v, want ErrLaneAttribution", err)
	}

	overlong := append(bytes.Repeat([]byte{0x80}, 10), 0x01) // 11-byte varint
	overflow := append(bytes.Repeat([]byte{0x80}, 9), 0x02)  // 10 bytes, past u64
	cases := map[string][]byte{
		"empty datagram":              {},
		"truncated after lane_id":     {0x07},
		"unterminated lane_id varint": {0x80},
		"non-minimal lane_id":         {0x87, 0x00, 0x01, 'x'}, // 7 in two bytes (terminal zero)
		"non-minimal zero lane_id":    {0x80, 0x00},
		"unterminated flow_id":        {0x07, 0x80},
		"non-minimal flow_id":         {0x07, 0x81, 0x00, 'x'},
		"lane_id varint overlong":     overlong,
		"lane_id varint overflow":     overflow,
	}
	for name, b := range cases {
		dg, keepalive, err := ParseLaneDatagram(b)
		if !errors.Is(err, ErrLaneAttribution) || keepalive {
			t.Errorf("%s (%x): dg=%+v keepalive=%v err=%v, want ErrLaneAttribution", name, b, dg, keepalive, err)
		}
	}
}
