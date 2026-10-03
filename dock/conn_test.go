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
	"errors"
	"testing"
	"time"
)

// fakeRPCStream records Abort and serves canned reads/writes.
type fakeRPCStream struct {
	aborted bool
	closed  bool
}

func (f *fakeRPCStream) Read(p []byte) (int, error)  { return 0, errors.New("eof") }
func (f *fakeRPCStream) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeRPCStream) Close() error                { f.closed = true; return nil }
func (f *fakeRPCStream) Abort()                      { f.aborted = true }

// TestRpcSatisfiesRPCStream is a compile-time assertion that *Rpc is a valid
// RPCStream, so consumers can pass a real Rpc to NewRPCConn.
func TestRpcSatisfiesRPCStream(t *testing.T) {
	var _ RPCStream = (*Rpc)(nil)
}

// TestNewRPCConnCloseAbortsAndRunsOnClose: Close aborts the RPC, runs onClose
// once, and the deadline setters are inert.
func TestNewRPCConnCloseAbortsAndRunsOnClose(t *testing.T) {
	stream := &fakeRPCStream{}
	closes := 0
	conn := NewRPCConn(stream, func() error { closes++; return nil })

	if err := conn.SetDeadline(time.Time{}); err != nil {
		t.Fatalf("SetDeadline error = %v", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	// Idempotent: a second Close neither re-aborts nor re-runs onClose.
	if err := conn.Close(); err != nil {
		t.Fatalf("second Close error = %v", err)
	}
	if !stream.aborted {
		t.Fatal("Close did not abort the RPC stream")
	}
	if stream.closed {
		t.Fatal("Close must abort the stream, not Close it (one RESET, no half-close)")
	}
	if closes != 1 {
		t.Fatalf("onClose ran %d times, want exactly 1", closes)
	}
}

// TestNewRPCConnNilOnClose: a nil onClose (the dock outlives the RPC) is
// accepted, and Close still aborts the stream.
func TestNewRPCConnNilOnClose(t *testing.T) {
	stream := &fakeRPCStream{}
	conn := NewRPCConn(stream, nil)
	if err := conn.Close(); err != nil {
		t.Fatalf("Close error = %v", err)
	}
	if !stream.aborted {
		t.Fatal("Close did not abort the RPC stream")
	}
}
