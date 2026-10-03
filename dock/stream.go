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
)

// Stream is one bidirectional stream on a dock's connection, with the
// same semantics on either transport except where noted. Dock.OpenStream
// returns one, and NewRPC wraps one as an RPC.
//
//   - Read and Write carry bytes in each direction independently.
//   - Close half-closes the write direction (FIN); reads continue until
//     the peer's FIN.
//   - CancelRead stops the read direction and asks the peer to stop
//     sending; CancelWrite resets the write direction. Each carries an
//     application error code, such as wire.DockCodeProtocol. On the
//     fallback transport, which has one reset frame for both
//     directions, either call resets the whole stream.
//   - SetReadDeadline bounds blocked and future reads; the zero time
//     removes the bound.
//
// On QUIC, a stream retires, and its stream credit returns to the side
// that opened it, only once both directions have ended. On either
// transport, finish a stream cleanly by closing the write direction and
// reading the peer's data to EOF, or end it with CancelRead and
// CancelWrite.
type Stream interface {
	io.Reader
	io.Writer
	Close() error
	CancelRead(code uint64)
	CancelWrite(code uint64)
	SetReadDeadline(t time.Time) error
}

// OpenStream opens a new bidirectional stream on the dock's connection
// and returns it without writing to it. It is the building block for a
// stream protocol this package does not implement; lanes, RPCs and
// events do not need it.
//
// The stream belongs to the caller: the dock never reads or writes it,
// and it ends when the caller finishes it or when the dock ends. The
// first byte the caller writes selects the stream's protocol at the
// edge, and the edge resets a stream that does not begin with a
// protocol it serves to this dock.
//
// On QUIC, OpenStream waits while the edge's stream limit allows no new
// stream. It returns when ctx is done or the dock ends.
func (d *Dock) OpenStream(ctx context.Context) (Stream, error) {
	s, err := d.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return s, nil
}
