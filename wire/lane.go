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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// lane.go: the lane wire format. Streams and datagram flows attach to an
// established lane with raw framing, not protobuf: the attribution header
// below is the entire per-stream wire overhead. The client and any other
// Go peer frame lanes with this code, which needs no QUIC implementation.

// StreamKindLane identifies a lane stream. It is the first byte of every
// lane stream, in both directions and on both transports. A length-prefixed
// protobuf stream always begins with 0x00, because every frame is far below
// 16 MiB; raw lane framing has no such property, so lane streams carry this
// explicit first-byte discriminant, including the streams the edge opens.
const StreamKindLane byte = 0x03

// LaneCodeDraining is the application error code, on QUIC and on the
// fallback transport, with which a draining lane refuses a new stream; it
// is sent as STOP_SENDING and RESET_STREAM. The opener establishes a new
// lane; the draining lane finishes its existing streams.
const LaneCodeDraining = 0x20

// Lane classes declare what may attach to a lane. lane_class is a u64
// bitset that shares the adapter-class bit space, so checking that every
// requested class is permitted by the target's adapter classes is one
// bitwise test. Bits are never reassigned, and the edge refuses a request
// naming a bit with no assigned class as an adapter mismatch.
const (
	// LaneClassStream permits native QUIC bidirectional streams to attach.
	LaneClassStream uint64 = 1 << 2
	// LaneClassFlow permits datagram flows to attach. It is refused at
	// lane establishment when any participating dock rides the fallback
	// transport, which has no datagram frame type.
	LaneClassFlow uint64 = 1 << 3
	// LaneClassIngressTarget lets the lane bind ingress listener traffic
	// to this dock.
	LaneClassIngressTarget uint64 = 1 << 4
	// LaneClassSpliceLeg lets the dock be one leg of a two-dock lane. It
	// is the bit of AdapterSplice; lanes read that bit as splice-leg, the
	// same bit and the same grant.
	LaneClassSpliceLeg uint64 = 1 << 5
)

// Stream security classes. The class is declarative attribution for
// policy, pooling and accounting, never a security claim: a peer is
// verified only by the inner end-to-end handshake. 0x00 and unassigned
// values are invalid on the wire.
const (
	// LaneStreamClassE2EMTLS declares inner TLS 1.3 mutual TLS between the
	// consumer's SVID and the workload's SVID.
	LaneStreamClassE2EMTLS byte = 0x01
	// LaneStreamClassPassthrough declares raw bytes; the application's own
	// protocol provides any security.
	LaneStreamClassPassthrough byte = 0x02
)

// LaneHeaderMaxLen bounds the opaque per-stream header: hdr_len is a u16
// on the wire.
const LaneHeaderMaxLen = 1<<16 - 1

// ErrLaneAttribution marks invalid attribution bytes: a bad or non-minimal
// varint, lane_id 0, an unassigned stream class, or a header that ends
// before hdr_len is satisfied. Receivers answer the violation by cancelling
// the stream with DockCodeProtocol.
var ErrLaneAttribution = errors.New("wire: malformed lane attribution")

// LaneStreamHeader is the attribution a lane stream begins with:
//
//	0x03 | varint lane_id | u8 stream_class | u16 hdr_len (BE) | hdr
//
// The varint is unsigned LEB128, the protobuf varint, because lane_id is a
// full u64 and exceeds the 2^62-1 range of the RFC 9000 varint. It is at
// most 10 bytes and must be minimal: one lane_id has exactly one wire form.
// Header is opaque and relayed verbatim; the fabric parses nothing inside
// it.
type LaneStreamHeader struct {
	// LaneID is the connection-scoped lane handle; 0 is invalid on the
	// wire.
	LaneID uint64
	// Class is the declared stream security class (LaneStreamClass*).
	Class byte
	// Header is the opaque per-stream application metadata, at most
	// LaneHeaderMaxLen bytes.
	Header []byte
}

// AppendLaneHeader appends h's attribution bytes, kind byte first, to
// dst and returns the extended slice. It refuses values with no legal
// wire form: LaneID 0, an unassigned Class, a Header past LaneHeaderMaxLen.
func AppendLaneHeader(dst []byte, h LaneStreamHeader) ([]byte, error) {
	if h.LaneID == 0 {
		return nil, fmt.Errorf("%w: lane_id 0", ErrLaneAttribution)
	}
	if h.Class != LaneStreamClassE2EMTLS && h.Class != LaneStreamClassPassthrough {
		return nil, fmt.Errorf("%w: stream class %#02x", ErrLaneAttribution, h.Class)
	}
	if len(h.Header) > LaneHeaderMaxLen {
		return nil, fmt.Errorf("%w: header %d bytes exceeds the u16 bound", ErrLaneAttribution, len(h.Header))
	}
	dst = append(dst, StreamKindLane)
	// binary.AppendUvarint emits the shortest unsigned LEB128 form; the
	// encoder is responsible for minimal encoding.
	dst = binary.AppendUvarint(dst, h.LaneID)
	dst = append(dst, h.Class, byte(len(h.Header)>>8), byte(len(h.Header)))
	return append(dst, h.Header...), nil
}

// ReadLaneHeader reads one attribution header from r. The kind byte has
// already been consumed by stream dispatch; reading starts at the
// lane_id varint. Reads are exact: no byte past the header is consumed,
// so the caller owns the payload from the first byte after the header. A
// violation of the header grammar returns ErrLaneAttribution (wrapped).
// Input that ends early returns the read error; an end after the first
// byte is reported as io.ErrUnexpectedEOF.
func ReadLaneHeader(r io.Reader) (LaneStreamHeader, error) {
	id, err := readMinimalUvarint(r)
	if err != nil {
		return LaneStreamHeader{}, err
	}
	if id == 0 {
		return LaneStreamHeader{}, fmt.Errorf("%w: lane_id 0", ErrLaneAttribution)
	}
	var rest [3]byte // stream_class, hdr_len (big-endian)
	if _, err := io.ReadFull(r, rest[:]); err != nil {
		return LaneStreamHeader{}, noEOF(err)
	}
	class := rest[0]
	if class != LaneStreamClassE2EMTLS && class != LaneStreamClassPassthrough {
		return LaneStreamHeader{}, fmt.Errorf("%w: stream class %#02x", ErrLaneAttribution, class)
	}
	hdr := make([]byte, int(rest[1])<<8|int(rest[2]))
	if _, err := io.ReadFull(r, hdr); err != nil {
		return LaneStreamHeader{}, noEOF(err)
	}
	return LaneStreamHeader{LaneID: id, Class: class, Header: hdr}, nil
}

// readMinimalUvarint decodes one unsigned LEB128 varint a byte at a time,
// with exact reads and nothing buffered past the varint. It enforces the
// header's varint rules: minimal form only (the final byte of a multi-byte
// encoding is never zero), at most 10 bytes, and a value within u64.
func readMinimalUvarint(r io.Reader) (uint64, error) {
	var x uint64
	var buf [1]byte
	for i := 0; i < 10; i++ {
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			if i > 0 {
				return 0, noEOF(err)
			}
			return 0, err
		}
		b := buf[0]
		if i == 9 && b > 0x01 {
			return 0, fmt.Errorf("%w: varint overflows u64", ErrLaneAttribution)
		}
		x |= uint64(b&0x7F) << (7 * i)
		if b&0x80 == 0 {
			if b == 0 && i > 0 {
				return 0, fmt.Errorf("%w: non-minimal varint", ErrLaneAttribution)
			}
			return x, nil
		}
	}
	return 0, fmt.Errorf("%w: varint exceeds 10 bytes", ErrLaneAttribution)
}

// noEOF maps a mid-grammar EOF to ErrUnexpectedEOF: a header that ends
// early is truncated, never a clean end.
func noEOF(err error) error {
	if errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// ---------------------------------------------------------------------
// Lane datagrams
// ---------------------------------------------------------------------

// LaneDatagram is one parsed lane datagram. Its attribution prefix
//
//	varint lane_id | varint flow_id | payload
//
// uses the same minimal-form LEB128 varints as the stream header, with no
// discriminator byte before it: the only other datagram form on a dock
// connection is the keepalive (a leading varint 0). FlowID is
// sender-scoped and opaque; it passes through the fabric untouched, and
// demultiplexing flows within a lane is the application's concern.
// Payload aliases the parsed datagram's bytes.
type LaneDatagram struct {
	// LaneID is the receiving connection's own lane handle; the edge
	// rewrites it hop by hop, so each end reads its own id.
	LaneID uint64
	// FlowID is the sender-scoped opaque flow identifier. Any u64 is
	// legal, zero included; only lane_id 0 is reserved.
	FlowID uint64
	// Payload is the flow bytes after the prefix; it may be empty.
	Payload []byte
}

// LaneKeepalive returns the canonical keepalive datagram, which signals
// transport activity: the single byte 0x00, the minimal encoding of the
// zero varint. lane_id 0 is invalid, so a leading zero varint only ever
// means activity: it is drained, never attributed, and never a violation.
func LaneKeepalive() []byte { return []byte{0x00} }

// AppendLaneDatagram appends the datagram attribution prefix and payload
// to dst and returns the extended slice. It refuses lane_id 0, the one
// value with no legal attributed wire form. Datagram flows are
// best-effort: there is no per-datagram refusal anywhere on the path, and
// a receiver silently drops malformed datagrams, so a successful send is
// never a delivery claim.
func AppendLaneDatagram(dst []byte, laneID, flowID uint64, payload []byte) ([]byte, error) {
	if laneID == 0 {
		return nil, fmt.Errorf("%w: lane_id 0", ErrLaneAttribution)
	}
	// binary.AppendUvarint emits the shortest unsigned LEB128 form; as for
	// the stream header, the encoder is responsible for minimal encoding.
	dst = binary.AppendUvarint(dst, laneID)
	dst = binary.AppendUvarint(dst, flowID)
	return append(dst, payload...), nil
}

// ParseLaneDatagram parses one lane datagram. keepalive reports the
// leading-zero-varint form (canonically the single byte 0x00): transport
// activity only, never parsed further and never a violation. Malformed
// attribution (a truncated, non-minimal or overlong varint, including a
// non-minimal encoding of zero) returns ErrLaneAttribution (wrapped); the
// receiver's answer is a silent drop, not an error reply. Payload aliases
// b.
func ParseLaneDatagram(b []byte) (dg LaneDatagram, keepalive bool, err error) {
	laneID, n, err := datagramUvarint(b)
	if err != nil {
		return LaneDatagram{}, false, err
	}
	if laneID == 0 {
		// A zero lane_id is activity only; the rest of the datagram is
		// not parsed.
		return LaneDatagram{}, true, nil
	}
	flowID, m, err := datagramUvarint(b[n:])
	if err != nil {
		return LaneDatagram{}, false, err
	}
	return LaneDatagram{LaneID: laneID, FlowID: flowID, Payload: b[n+m:]}, false, nil
}

// datagramUvarint decodes one minimal-form LEB128 varint from the head
// of b, enforcing the same rules readMinimalUvarint enforces on streams.
// It works on a slice because a datagram arrives whole: truncation is
// malformed attribution, never a pending read.
func datagramUvarint(b []byte) (uint64, int, error) {
	v, n := binary.Uvarint(b)
	if n == 0 {
		return 0, 0, fmt.Errorf("%w: truncated varint", ErrLaneAttribution)
	}
	if n < 0 {
		return 0, 0, fmt.Errorf("%w: varint overflows u64", ErrLaneAttribution)
	}
	if n > 1 && b[n-1] == 0 {
		return 0, 0, fmt.Errorf("%w: non-minimal varint", ErrLaneAttribution)
	}
	return v, n, nil
}
