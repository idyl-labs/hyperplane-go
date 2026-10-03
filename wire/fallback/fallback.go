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

// Package fallback implements fallback/1, the TCP+TLS dock transport for
// networks that block UDP. One TLS 1.3 connection carries multiplexed
// streams in place of QUIC.
//
// The fallback transport has fewer properties than QUIC: it carries no
// datagrams, it has no connection migration, a lost TCP segment stalls
// every stream on the connection (head-of-line blocking), and it recovers
// less gracefully when many connections reconnect at once. Hyperplane
// records which transport each dock uses, so operators can see docks that
// run degraded. No correctness property depends on QUIC being available.
//
// fallback/1 carries exactly the stream shapes the dock protocol needs:
// bidirectional streams opened by either side (the control channel and
// RPCs), unidirectional streams opened by the edge (event delivery), a
// PING frame in place of keepalive datagrams, and a connection close that
// carries the dock application code, so a closed dock is classified the
// same way on either transport. The protocol evolves only additively.
//
// Frames are header(9) || payload:
//
//	type  u8
//	sid   u32 big-endian   stream id; 0 for connection-level frames
//	len   u32 big-endian   payload length, capped at MaxFramePayload
//
// The client opens odd stream ids starting at 1; the server opens even
// stream ids starting at 2. Flow control is credit-based per stream so
// that every buffer is bounded: a receiver grants InitialWindow bytes and
// replenishes the credit with WINDOW frames as its consumer reads, and a
// sender blocks at zero credit. A peer that sends past its credit is a
// protocol violation, and the connection is closed rather than buffering
// without bound.
package fallback

import (
	"errors"
	"fmt"
)

// ALPN is the TLS application protocol name for fallback/1. It differs
// from the QUIC transport's ALPN because the wire layers differ; a dialer
// always knows which one it speaks.
const ALPN = "idyl-fallback/1"

// Frame types.
const (
	typeOpenBidi byte = 0x01 // open a bidirectional stream
	typeOpenUni  byte = 0x02 // open a unidirectional stream (opener to peer)
	typeData     byte = 0x03 // stream payload bytes
	typeFin      byte = 0x04 // half-close: no more data from this side
	typeReset    byte = 0x05 // abort the stream, both directions; payload u64 code
	typeWindow   byte = 0x06 // flow-control credit; payload u32 increment
	typePing     byte = 0x07 // transport activity (keepalive); no payload. Receipt alone resets the receiver's idle clock; this implementation never replies to an inbound PING.
	typeClose    byte = 0x08 // connection close; payload u64 code || reason
)

const (
	headerLen = 9

	// MaxFramePayload bounds one frame's payload (a DATA chunk).
	MaxFramePayload = 64 << 10

	// InitialWindow is the per-stream receive credit. It bounds the
	// bytes buffered per stream: a sender blocks past it until the
	// consumer reads.
	InitialWindow = 256 << 10

	// acceptBacklog bounds peer-opened streams awaiting Accept.
	acceptBacklog = 64
)

// Sentinel errors. Match them with errors.Is.
var (
	// ErrConnClosed is wrapped by the error of every operation on a closed
	// connection. The close cause is available from the connection's
	// context through context.Cause.
	ErrConnClosed = errors.New("fallback: connection closed")
	// ErrStreamReset marks a stream aborted by a RESET frame.
	ErrStreamReset = errors.New("fallback: stream reset")
	// ErrProtocol marks a protocol violation by the peer, or a frame this
	// side refuses to send. A received violation closes the connection.
	ErrProtocol = errors.New("fallback: protocol violation")
)

// StreamResetError is the terminal error of a stream aborted by a RESET
// frame. It carries the frame's u64 application code and plays the role
// that *quic.StreamError plays on the QUIC transport.
// errors.Is(err, ErrStreamReset) holds for every StreamResetError.
type StreamResetError struct {
	Code   uint64
	Remote bool // true when the peer sent the RESET; false for a local CancelRead or CancelWrite
}

func (e StreamResetError) Error() string {
	if e.Remote {
		return fmt.Sprintf("fallback: stream reset: code %d", e.Code)
	}
	return fmt.Sprintf("fallback: stream reset: code %d (local)", e.Code)
}

// Is reports whether target is ErrStreamReset.
func (StreamResetError) Is(target error) bool { return target == ErrStreamReset }

// ConnError is the close cause of a connection closed by a CLOSE frame,
// sent or received. It plays the role of a QUIC application error and
// carries the same dock application codes (the wire.DockCode constants).
// Remote is true when the peer sent the CLOSE frame.
type ConnError struct {
	Code   uint64
	Reason string
	Remote bool
}

func (e *ConnError) Error() string {
	side := "local"
	if e.Remote {
		side = "remote"
	}
	return "fallback: connection closed (" + side + "): " + e.Reason
}

// IdleTimeoutError is the close cause when the peer sends no frame for
// longer than the idle window. It is how this transport detects a peer
// that disappeared without closing the connection.
type IdleTimeoutError struct{}

func (IdleTimeoutError) Error() string { return "fallback: idle timeout" }
