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

package dock

import (
	"context"
	"io"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
)

// drainTimeout bounds the drain that follows the last frame on a one-shot
// delivery stream. A QUIC stream is retired, and its stream credit
// returned to the opener, only once both directions are closed, so the
// receiver reads the peer's FIN to EOF. The drain is bounded so that a
// peer that never sends FIN cannot hold the stream open; on timeout the
// stream is reset, which also retires it. Reset is used only as this
// timeout fallback: clean completion is always FIN and drain, because a
// reset on the success path can discard the peer's final frame. It is a
// variable so tests can shorten it.
var drainTimeout = 3 * time.Second

// drainReceive reads an edge-opened unidirectional stream (an event push)
// to EOF after its single frame, bounded by drainTimeout, so the stream
// retires and its credit returns to the edge. On timeout or any other
// error it cancels the read side.
func drainReceive(s transportReceiveStream) {
	_ = s.SetReadDeadline(time.Now().Add(drainTimeout))
	if _, err := io.Copy(io.Discard, s); err != nil {
		s.CancelRead(wire.DockCodeProtocol)
	}
}

// RPC is one inbound RPC: an open bidirectional byte pipe between the
// RPC's opener and this dock.
type RPC struct {
	stream transportStream
}

func (r *RPC) Read(p []byte) (int, error)  { return r.stream.Read(p) }
func (r *RPC) Write(p []byte) (int, error) { return r.stream.Write(p) }

// Close half-closes the write side (FIN); reads continue until the peer's
// FIN. To finish an RPC cleanly, close the write side and read the peer's
// data to EOF: once both directions have ended, the stream retires and its
// credit returns without a reset. Use Abort only to give up.
func (r *RPC) Close() error { return r.stream.Close() }

// Abort resets both directions of the RPC at once.
func (r *RPC) Abort() {
	r.stream.CancelRead(wire.DockCodeProtocol)
	r.stream.CancelWrite(wire.DockCodeProtocol)
}

// AcceptEvent blocks for the next pushed event and returns its payload.
// The edge opens one unidirectional stream per event. AcceptEvent reads
// the event's single frame and then drains the stream to EOF, so the
// stream retires and its credit returns to the edge.
func (d *Dock) AcceptEvent(ctx context.Context) ([]byte, error) {
	s, err := d.conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	var push dpb.EventPush
	if err := wire.ReadFrame(s, &push, 0); err != nil {
		s.CancelRead(wire.DockCodeProtocol)
		return nil, err
	}
	// Read to the edge's FIN so the stream retires and its credit returns.
	// Without this, every event would hold one unit of the dock's incoming
	// unidirectional stream limit, and event delivery would stall.
	drainReceive(s)
	return push.GetPayload(), nil
}

// AcceptRPC blocks for the next inbound RPC and returns the metadata the
// opener supplied together with the byte pipe. Inbound bidirectional
// streams are told apart by their first byte: every RPC begins with a
// length-prefixed frame whose first byte is 0x00 (the 4-byte big-endian
// length is capped at wire.DefaultMaxFrame), and every lane stream begins with
// wire.StreamKindLane. RPCs and lane streams therefore share one dock.
// RPC streams that arrived before the dock ended can still be accepted
// after it ends.
func (d *Dock) AcceptRPC(ctx context.Context) ([]byte, *RPC, error) {
	d.ensurePump()
	set := d.laneset()
	var s transportStream
	select {
	case ps := <-set.rpc:
		s = ps
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-d.conn.Context().Done():
		// Streams routed before the connection ended stay claimable.
		select {
		case ps := <-set.rpc:
			s = ps
		default:
			set.mu.Lock()
			err := set.pumpErr
			set.mu.Unlock()
			if err == nil {
				err = d.conn.Context().Err()
			}
			return nil, nil, err
		}
	}
	var open dpb.RpcOpen
	if err := wire.ReadFrame(s, &open, 0); err != nil {
		// A malformed opening frame must release the edge-opened stream in
		// both directions, or every bad open would strand one stream.
		s.CancelRead(wire.DockCodeProtocol)
		s.CancelWrite(wire.DockCodeProtocol)
		return nil, nil, err
	}
	return open.GetMetadata(), &RPC{stream: s}, nil
}
