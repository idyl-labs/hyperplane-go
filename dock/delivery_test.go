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

// delivery_test.go: the inbound RPC path (AcceptRPC) against scripted
// edge-opened streams. The transportConn/transportStream seam lets stream
// ownership be checked without a live connection: a well-formed RpcOpen
// preface hands the stream to the returned RPC, and a broken one releases
// it in both directions.

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
)

// acceptConn serves its one stream once, then blocks until the context
// ends. The dispatch pump keeps accepting, and a fake that re-served the
// same exhausted stream would race the test's release assertions.
type acceptConn struct {
	s     transportStream
	taken bool
}

func (c *acceptConn) OpenStreamSync(context.Context) (transportStream, error) { panic("not used") }
func (c *acceptConn) AcceptStream(ctx context.Context) (transportStream, error) {
	if c.taken {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	c.taken = true
	return c.s, nil
}
func (c *acceptConn) AcceptUniStream(context.Context) (transportReceiveStream, error) {
	panic("not used")
}
func (c *acceptConn) SendKeepalive() error                { panic("not used") }
func (c *acceptConn) CloseWithError(uint64, string) error { panic("not used") }
func (c *acceptConn) Context() context.Context            { return context.Background() }
func (c *acceptConn) Resumed() bool                       { return false }

// recordingStream serves a scripted reply and records its teardown, so a
// leaked stream (one never released on an error path) is observable.
type recordingStream struct {
	serve       *bytes.Reader
	err         error
	closed      bool
	cancelRead  bool
	cancelWrite bool
}

func (s *recordingStream) Read(p []byte) (int, error) {
	if s.serve.Len() == 0 {
		return 0, s.err
	}
	return s.serve.Read(p)
}
func (s *recordingStream) Write(p []byte) (int, error)     { return len(p), nil }
func (s *recordingStream) Close() error                    { s.closed = true; return nil }
func (s *recordingStream) CancelRead(uint64)               { s.cancelRead = true }
func (s *recordingStream) CancelWrite(uint64)              { s.cancelWrite = true }
func (s *recordingStream) SetReadDeadline(time.Time) error { return nil }

// released reports whether the stream was torn down by either teardown verb.
func (s *recordingStream) released() bool { return s.closed || s.cancelRead || s.cancelWrite }

// TestAcceptRPCReturnsPipe: on an edge-opened stream, the RpcOpen preface
// surfaces the opener's metadata and ownership of the stream transfers to
// the returned RPC, so a successful accept must not release it.
func TestAcceptRPCReturnsPipe(t *testing.T) {
	var frame bytes.Buffer
	if err := wire.WriteFrame(&frame, &dpb.RpcOpen{Metadata: []byte("meta")}); err != nil {
		t.Fatal(err)
	}
	s := &recordingStream{serve: bytes.NewReader(frame.Bytes()), err: io.EOF}
	d := &Dock{conn: &acceptConn{s: s}}

	metadata, rpc, err := d.AcceptRPC(context.Background())
	if err != nil {
		t.Fatalf("AcceptRPC error = %v", err)
	}
	if string(metadata) != "meta" {
		t.Fatalf("metadata = %q, want meta", metadata)
	}
	if rpc == nil {
		t.Fatal("AcceptRPC returned nil pipe")
	}
	if s.released() {
		t.Fatal("AcceptRPC released the stream on success; ownership must transfer to the RPC")
	}
}

// TestAcceptRPCReleasesStreamOnBadPreface: a broken RpcOpen preface must
// cancel the edge-opened stream in both directions. Otherwise every
// malformed open strands one stream, and with it the stream credit the
// edge needs to keep opening new ones.
func TestAcceptRPCReleasesStreamOnBadPreface(t *testing.T) {
	// A frame header declaring 10 bytes, then EOF: ReadFrame must fail.
	truncated := []byte{0x00, 0x00, 0x00, 0x0A}
	s := &recordingStream{serve: bytes.NewReader(truncated), err: io.EOF}
	d := &Dock{conn: &acceptConn{s: s}}

	if _, _, err := d.AcceptRPC(context.Background()); err == nil {
		t.Fatal("AcceptRPC with a truncated preface must return an error")
	}
	if !s.cancelRead || !s.cancelWrite {
		t.Fatal("AcceptRPC leaked the stream on a bad preface: both directions must be canceled")
	}
}
