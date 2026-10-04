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
	"errors"
	"fmt"
	"io"
	"sync"
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

// NakError is a typed refusal of a delivery verb (SendEvent, OpenRPC or
// OpenLane) by the edge.
type NakError struct {
	Code dpb.NakCode
}

func (e NakError) Error() string {
	return fmt.Sprintf("dock: delivery refused: %s", e.Code)
}

// deliveryWatch resets a delivery stream in both directions when the
// verb's context ends, so a verb waiting on the edge returns promptly
// instead of waiting for the stream or the dock to end.
type deliveryWatch struct {
	stop     func() bool
	reset    chan struct{}
	once     sync.Once
	canceled bool
}

func watchDelivery(ctx context.Context, s transportStream) *deliveryWatch {
	w := &deliveryWatch{reset: make(chan struct{})}
	w.stop = context.AfterFunc(ctx, func() {
		defer close(w.reset)
		s.CancelRead(wire.DockCodeProtocol)
		s.CancelWrite(wire.DockCodeProtocol)
	})
	return w
}

// release ends the watch and reports whether the context ended first.
// Once it returns, the stream is either reset already or never will be by
// the watch. It is safe to call more than once.
func (w *deliveryWatch) release() bool {
	w.once.Do(func() {
		if !w.stop() {
			<-w.reset
			w.canceled = true
		}
	})
	return w.canceled
}

// releaseDelivery ends the watch after the stream is finished, and adds
// the context's error to a verb error caused by the context ending, so
// callers can classify it with errors.Is.
func releaseDelivery(ctx context.Context, w *deliveryWatch, err *error) {
	if w.release() && *err != nil && !errors.Is(*err, ctx.Err()) {
		*err = errors.Join(*err, ctx.Err())
	}
}

// openDelivery opens a one-shot delivery stream, watched by ctx, and
// writes its kind byte. The context's deadline, if any, also bounds
// reading the reply. If the kind byte cannot be written, the stream is
// reset in both directions.
func (d *Dock) openDelivery(ctx context.Context) (transportStream, *deliveryWatch, error) {
	s, err := d.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, nil, err
	}
	w := watchDelivery(ctx, s)
	if _, err := s.Write([]byte{wire.StreamKindDelivery}); err != nil {
		s.CancelRead(wire.DockCodeProtocol)
		s.CancelWrite(wire.DockCodeProtocol)
		releaseDelivery(ctx, w, &err)
		return nil, nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = s.SetReadDeadline(deadline)
	}
	return s, w, nil
}

// SendEvent delivers one payload to the dock that locator names. The
// locator is sealed by the fabric and opaque to the caller. SendEvent is
// one-way and best-effort: a nil error means the edge acknowledged that
// the payload entered the target dock's stream, not that the application
// handled it. A refusal is a NakError. If ctx ends before the edge
// replies, SendEvent returns promptly with an error that matches
// ctx.Err(). The delivery stream is finished on every path.
func (d *Dock) SendEvent(ctx context.Context, locator, payload []byte) (err error) {
	s, w, err := d.openDelivery(ctx)
	if err != nil {
		return err
	}
	defer func() {
		FinishStream(s)
		releaseDelivery(ctx, w, &err)
	}()
	if err := wire.WriteFrame(s, &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_SendEvent{
		SendEvent: &dpb.SendEvent{Locator: locator, Payload: payload},
	}}); err != nil {
		return err
	}
	var reply dpb.EdgeToRequester
	if err := wire.ReadFrame(s, &reply, 0); err != nil {
		return err
	}
	switch m := reply.GetMsg().(type) {
	case *dpb.EdgeToRequester_Ack:
		return nil
	case *dpb.EdgeToRequester_Nak:
		return NakError{Code: m.Nak.GetCode()}
	}
	return errors.New("dock: unexpected delivery reply")
}

// OpenRPC opens an RPC to the dock that locator names: a bidirectional
// byte pipe whose far end the target dock receives from AcceptRPC, with
// metadata, which the fabric does not interpret. A refusal is a NakError.
// If ctx ends before the RPC is open, OpenRPC returns promptly with an
// error that matches ctx.Err(). On any error the stream is finished; on
// success it belongs to the returned RPC, and ctx no longer affects it.
func (d *Dock) OpenRPC(ctx context.Context, locator, metadata []byte) (_ *RPC, err error) {
	s, w, err := d.openDelivery(ctx)
	if err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			FinishStream(s)
			releaseDelivery(ctx, w, &err)
		}
	}()
	if err := wire.WriteFrame(s, &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_OpenRpc{
		OpenRpc: &dpb.OpenRpc{Locator: locator, Metadata: metadata},
	}}); err != nil {
		return nil, err
	}
	var reply dpb.EdgeToRequester
	if err := wire.ReadFrame(s, &reply, 0); err != nil {
		return nil, err
	}
	switch m := reply.GetMsg().(type) {
	case *dpb.EdgeToRequester_RpcOpened:
		if w.release() {
			// ctx ended as the RPC opened: the stream is already reset.
			return nil, ctx.Err()
		}
		_ = s.SetReadDeadline(time.Time{})
		handedOff = true
		return &RPC{stream: s}, nil
	case *dpb.EdgeToRequester_Nak:
		return nil, NakError{Code: m.Nak.GetCode()}
	}
	return nil, errors.New("dock: unexpected delivery reply")
}

// RPC is one RPC: an open bidirectional byte pipe between the RPC's two
// ends. OpenRPC opens one, AcceptRPC returns inbound ones, and NewRPC
// makes one from a stream.
type RPC struct {
	stream transportStream
}

// NewRPC returns an RPC over s, which must not be nil. It serves a
// stream protocol that establishes an RPC on a stream from
// Dock.OpenStream: once the protocol hands over the stream, the RPC
// behaves exactly as one from AcceptRPC. The RPC takes ownership of s.
func NewRPC(s Stream) *RPC { return &RPC{stream: s} }

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
