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
	"net"
	"sync"
	"time"
)

// ReportRPCMetadata is the well-known RPC metadata that marks a report
// RPC. A dock only accepts RPCs; it cannot open one toward the peer it
// wants to report to. That peer therefore opens an RPC carrying this
// metadata, and the dock runs its own request/response session over the
// accepted RPC (typically through NewRPCConn). The fabric treats RPC
// metadata as opaque; this value is an agreement between the two
// endpoints only.
const ReportRPCMetadata = "reports/v1"

// RPCStream is the byte-stream surface of an RPC. *Rpc satisfies it.
// NewRPCConn adapts it to net.Conn; as an interface it also lets callers
// substitute a fake in tests.
type RPCStream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	Abort()
}

// NewRPCConn adapts an RPCStream to net.Conn so that a stream or session
// protocol (for example a stream multiplexer) can run over an RPC.
//
// The returned connection's Close aborts the RPC, resetting both
// directions at once, and then runs onClose if it is non-nil; Close runs
// this sequence once and returns the same result on every call. Pass the
// dock's Close as onClose when the dock exists only for this RPC and must
// end with it; pass nil when the dock outlives the RPC. An RPC has no
// deadline support, so the deadline setters are no-ops, and both
// addresses are placeholders.
func NewRPCConn(stream RPCStream, onClose func() error) net.Conn {
	return &rpcStreamConn{stream: stream, onClose: onClose}
}

type rpcStreamConn struct {
	stream  RPCStream
	onClose func() error

	once     sync.Once
	closeErr error
}

func (c *rpcStreamConn) Read(p []byte) (int, error)  { return c.stream.Read(p) }
func (c *rpcStreamConn) Write(p []byte) (int, error) { return c.stream.Write(p) }

func (c *rpcStreamConn) Close() error {
	c.once.Do(func() {
		c.stream.Abort()
		if c.onClose != nil {
			c.closeErr = c.onClose()
		}
	})
	return c.closeErr
}

func (c *rpcStreamConn) LocalAddr() net.Addr              { return rpcAddr{} }
func (c *rpcStreamConn) RemoteAddr() net.Addr             { return rpcAddr{} }
func (c *rpcStreamConn) SetDeadline(time.Time) error      { return nil }
func (c *rpcStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *rpcStreamConn) SetWriteDeadline(time.Time) error { return nil }

type rpcAddr struct{}

func (rpcAddr) Network() string { return "hyperplane-rpc" }
func (rpcAddr) String() string  { return "hyperplane-rpc" }
