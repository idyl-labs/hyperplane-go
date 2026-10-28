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

// Package datadock is the contract of a stream to a Node's data dock: the
// principal a client names the data dock by, the header a client puts in
// each lane stream's attribution, and the reply the data dock writes before
// any other byte.
//
// A client opens one STREAM lane to a Node's data dock (delivery/2
// OpenDataDockLane) and one lane stream, of stream class e2e-mtls, per
// connection to a Computer that Node runs. The stream's attribution header
// carries Header: which Micropod the connection is for, and the Activation
// epoch the client expects to find there. The data dock answers with one
// Reply, then relays the stream's bytes to and from that Micropod's
// endpoint. The client sends its TLS ClientHello right after the header,
// without waiting for the reply, so the reply costs no round trip; it reads
// the reply before the endpoint's first byte.
//
// The data dock relays bytes it cannot read: the client's TLS runs end to
// end with the endpoint inside the Micropod. Nothing in this package is
// identity or authority. The header names a target; the endpoint's TLS and
// the session's grant decide what the client may do there.
package datadock

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// HeaderVersion is the version byte of the header this package encodes.
const HeaderVersion = 1

// HeaderBytes is the exact length of an encoded Header.
const HeaderBytes = 1 + 16 + 8 + 8

// MaxSequence and MaxEpoch bound a Header's Micropod sequence and
// Activation epoch.
const (
	MaxSequence = 1<<53 - 1
	MaxEpoch    = 1<<63 - 1
)

// MaxReasonBytes bounds a Reply's reason.
const MaxReasonBytes = 64

// ErrMalformed is wrapped by every decode refusal in this package.
var ErrMalformed = errors.New("datadock: malformed")

// Principal returns the SPIFFE ID of the data dock of node in the Zone whose
// trust domain is zoneTrustDomain ({zone}.zone.{network}):
// spiffe://{zoneTrustDomain}/node/{node}/data-dock.
func Principal(zoneTrustDomain, node string) (string, error) {
	if !strings.Contains(zoneTrustDomain, ".zone.") {
		return "", fmt.Errorf("%w: %q is not a Zone trust domain", ErrMalformed, zoneTrustDomain)
	}
	td, err := spiffeid.TrustDomainFromString(zoneTrustDomain)
	if err != nil || td.Name() != zoneTrustDomain {
		return "", fmt.Errorf("%w: %q is not a Zone trust domain", ErrMalformed, zoneTrustDomain)
	}
	id, err := spiffeid.FromSegments(td, "node", node, "data-dock")
	if err != nil {
		return "", fmt.Errorf("%w: node ID %q is not one path segment", ErrMalformed, node)
	}
	return id.String(), nil
}

// Header names the Micropod a lane stream is for: its host Pod and its
// sequence within the host, and the Activation epoch the client expects to
// find running there.
type Header struct {
	// Host is the host Pod's ID, a UUID in its 16 bytes.
	Host     [16]byte
	Sequence uint64
	Epoch    uint64
}

// Validate checks a Header's ranges.
func (h Header) Validate() error {
	switch {
	case h.Host == [16]byte{}:
		return fmt.Errorf("%w: host is the nil UUID", ErrMalformed)
	case h.Sequence < 1 || h.Sequence > MaxSequence:
		return fmt.Errorf("%w: sequence %d is outside 1 to %d", ErrMalformed, h.Sequence, uint64(MaxSequence))
	case h.Epoch < 1 || h.Epoch > MaxEpoch:
		return fmt.Errorf("%w: epoch %d is outside 1 to %d", ErrMalformed, h.Epoch, uint64(MaxEpoch))
	}
	return nil
}

// Encode returns the header's HeaderBytes: the version, the host's 16 bytes,
// then the sequence and the epoch as big-endian 64-bit integers.
func (h Header) Encode() ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}
	out := make([]byte, HeaderBytes)
	out[0] = HeaderVersion
	copy(out[1:17], h.Host[:])
	binary.BigEndian.PutUint64(out[17:25], h.Sequence)
	binary.BigEndian.PutUint64(out[25:33], h.Epoch)
	return out, nil
}

// DecodeHeader decodes exactly HeaderBytes. Any other length, another
// version, and any value out of range are refused.
func DecodeHeader(raw []byte) (Header, error) {
	if len(raw) != HeaderBytes {
		return Header{}, fmt.Errorf("%w: header is %d bytes, want %d", ErrMalformed, len(raw), HeaderBytes)
	}
	if raw[0] != HeaderVersion {
		return Header{}, fmt.Errorf("%w: header version %d", ErrMalformed, raw[0])
	}
	var h Header
	copy(h.Host[:], raw[1:17])
	h.Sequence = binary.BigEndian.Uint64(raw[17:25])
	h.Epoch = binary.BigEndian.Uint64(raw[25:33])
	if err := h.Validate(); err != nil {
		return Header{}, err
	}
	return h, nil
}

// Code is a Reply's outcome.
type Code uint8

// Reply codes. Every code but CodeLinked ends the stream after the reply.
const (
	// CodeLinked: the stream is linked to the Micropod's endpoint; the
	// endpoint's bytes follow.
	CodeLinked Code = 0
	// CodeMalformed: the header or the stream class is not this contract's.
	CodeMalformed Code = 1
	// CodeNotHere: no Micropod of the client's Account with that host and
	// sequence runs on this Node. A Micropod of another Account is not
	// distinguished from one that does not exist.
	CodeNotHere Code = 2
	// CodeStaleEpoch: the Micropod runs another Activation than the epoch
	// named; the client reads the Computer's placement again.
	CodeStaleEpoch Code = 3
	// CodeEndpointUnavailable: the Micropod's endpoint was not ready in
	// time; the client may try again.
	CodeEndpointUnavailable Code = 4
	// CodeAtCapacity: the data dock relays as many connections as it can.
	CodeAtCapacity Code = 5
	// CodeNodeUnavailable: the data dock cannot reach its Node's daemon.
	CodeNodeUnavailable Code = 6
)

// Reasons are the reason words the data dock writes with each code.
var reasons = map[Code]string{
	CodeLinked:              "",
	CodeMalformed:           "malformed",
	CodeNotHere:             "not-here",
	CodeStaleEpoch:          "stale-epoch",
	CodeEndpointUnavailable: "endpoint-unavailable",
	CodeAtCapacity:          "at-capacity",
	CodeNodeUnavailable:     "node-unavailable",
}

// Reason returns the reason word the data dock writes with code, and
// whether code is one this package knows.
func (c Code) Reason() (string, bool) {
	reason, ok := reasons[c]
	return reason, ok
}

// Reply is the data dock's answer to a lane stream: one code byte, one
// length byte, then that many bytes of a reason in lowercase letters and
// hyphens, empty for CodeLinked. A reader must accept a code it does not
// know as a refusal.
type Reply struct {
	Code   Code
	Reason string
}

// Linked reports whether the reply links the stream.
func (r Reply) Linked() bool { return r.Code == CodeLinked }

// Encode returns the reply's bytes.
func (r Reply) Encode() ([]byte, error) {
	if err := validateReason(r); err != nil {
		return nil, err
	}
	return append([]byte{byte(r.Code), byte(len(r.Reason))}, r.Reason...), nil
}

// NewReply returns the reply the data dock writes for code.
func NewReply(code Code) (Reply, error) {
	reason, ok := code.Reason()
	if !ok {
		return Reply{}, fmt.Errorf("%w: unknown reply code %d", ErrMalformed, code)
	}
	return Reply{Code: code, Reason: reason}, nil
}

// ReadReply reads one reply from r and nothing after it.
func ReadReply(r io.Reader) (Reply, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return Reply{}, fmt.Errorf("read the data dock's reply: %w", err)
	}
	reason := make([]byte, head[1])
	if _, err := io.ReadFull(r, reason); err != nil {
		return Reply{}, fmt.Errorf("read the data dock's reply: %w", err)
	}
	reply := Reply{Code: Code(head[0]), Reason: string(reason)}
	if err := validateReason(reply); err != nil {
		return Reply{}, err
	}
	return reply, nil
}

func validateReason(r Reply) error {
	if r.Code == CodeLinked && r.Reason != "" {
		return fmt.Errorf("%w: a linked reply carries a reason", ErrMalformed)
	}
	if r.Code != CodeLinked && r.Reason == "" {
		return fmt.Errorf("%w: a refusal carries no reason", ErrMalformed)
	}
	if len(r.Reason) > MaxReasonBytes {
		return fmt.Errorf("%w: reason is longer than %d bytes", ErrMalformed, MaxReasonBytes)
	}
	for _, c := range r.Reason {
		if (c < 'a' || c > 'z') && c != '-' {
			return fmt.Errorf("%w: reason holds %q", ErrMalformed, c)
		}
	}
	return nil
}
