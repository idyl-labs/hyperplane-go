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

package fallback_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

// TestWireConstants pins the values a peer must agree on: the ALPN name
// both ends negotiate, the per-frame payload cap, and the initial
// per-stream credit. Changing any of them breaks interoperability.
func TestWireConstants(t *testing.T) {
	if fallback.ALPN != "idyl-fallback/1" {
		t.Errorf("ALPN = %q", fallback.ALPN)
	}
	if fallback.MaxFramePayload != 65536 {
		t.Errorf("MaxFramePayload = %d", fallback.MaxFramePayload)
	}
	if fallback.InitialWindow != 262144 {
		t.Errorf("InitialWindow = %d", fallback.InitialWindow)
	}
}

// TestErrorRendering pins the text of every error type. Callers classify
// with errors.Is and errors.As, but the rendered text appears in logs and
// must stay stable and identify the side that acted.
func TestErrorRendering(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{fallback.ErrConnClosed, "fallback: connection closed"},
		{fallback.ErrStreamReset, "fallback: stream reset"},
		{fallback.ErrProtocol, "fallback: protocol violation"},
		{fallback.StreamResetError{Code: 42, Remote: true}, "fallback: stream reset: code 42"},
		{fallback.StreamResetError{Code: 42}, "fallback: stream reset: code 42 (local)"},
		{fallback.StreamResetError{Code: 1<<64 - 1, Remote: true}, "fallback: stream reset: code 18446744073709551615"},
		{&fallback.ConnError{Code: 0x10, Reason: "drain"}, "fallback: connection closed (local): drain"},
		{&fallback.ConnError{Code: 0x10, Reason: "drain", Remote: true}, "fallback: connection closed (remote): drain"},
		{&fallback.ConnError{Remote: true}, "fallback: connection closed (remote): "},
		{fallback.IdleTimeoutError{}, "fallback: idle timeout"},
	}
	for _, tc := range cases {
		if got := tc.err.Error(); got != tc.want {
			t.Errorf("%#v.Error() = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestErrorClassification checks that each error type matches exactly its
// own class, also through wrapping: a reset is ErrStreamReset and nothing
// else, and close causes are matched with errors.As, never mistaken for a
// reset or a protocol violation.
func TestErrorClassification(t *testing.T) {
	sentinels := []error{fallback.ErrConnClosed, fallback.ErrStreamReset, fallback.ErrProtocol}
	const none = -1
	cases := []struct {
		name string
		err  error
		is   int // index in sentinels of the one class err matches, or none
	}{
		{"remote reset", fallback.StreamResetError{Code: 1, Remote: true}, 1},
		{"local reset", fallback.StreamResetError{Code: 1}, 1},
		{"wrapped reset", fmt.Errorf("read: %w", fallback.StreamResetError{Code: 2}), 1},
		{"conn error", &fallback.ConnError{Code: 3}, none},
		{"idle timeout", fallback.IdleTimeoutError{}, none},
		{"closed by conn error", fmt.Errorf("%w: %w", fallback.ErrConnClosed, &fallback.ConnError{Code: 3}), 0},
	}
	for _, tc := range cases {
		for i, s := range sentinels {
			if got, want := errors.Is(tc.err, s), i == tc.is; got != want {
				t.Errorf("%s: errors.Is(_, %v) = %t, want %t", tc.name, s, got, want)
			}
		}
	}

	var sre fallback.StreamResetError
	if err := fmt.Errorf("op: %w", fallback.StreamResetError{Code: 7, Remote: true}); !errors.As(err, &sre) || sre.Code != 7 || !sre.Remote {
		t.Errorf("errors.As StreamResetError = %+v", sre)
	}
	var ce *fallback.ConnError
	if err := fmt.Errorf("%w: %w", fallback.ErrConnClosed, &fallback.ConnError{Code: 9, Reason: "r", Remote: true}); !errors.As(err, &ce) || ce.Code != 9 || ce.Reason != "r" || !ce.Remote {
		t.Errorf("errors.As ConnError = %+v", ce)
	}
	var idle fallback.IdleTimeoutError
	if err := fmt.Errorf("%w: %w", fallback.ErrConnClosed, fallback.IdleTimeoutError{}); !errors.As(err, &idle) {
		t.Error("errors.As IdleTimeoutError failed through wrapping")
	}
	// A reset with one code is not a reset with another: errors.Is
	// compares the typed value exactly before consulting the sentinel.
	if errors.Is(fallback.StreamResetError{Code: 1}, fallback.StreamResetError{Code: 2}) {
		t.Error("resets with different codes compared equal")
	}
}
