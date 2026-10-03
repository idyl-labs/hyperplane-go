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
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/idyl-labs/hyperplane-go/wire"
	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

// transport_test.go: the transport selection rule in dialTransport, which
// tries QUIC first and then the TCP+TLS fallback; the QUIC time slice's
// derivation from the caller's budget; and ForceFallback. The individual
// dial legs are covered in alpn_test.go.

// deadQUICEndpoint allocates a UDP socket that swallows every datagram. A
// QUIC dial against it fails by silence (the blocked-UDP case the fallback
// exists for), never by refusal, so the QUIC leg consumes its whole slice
// before selection moves on.
func deadQUICEndpoint(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().String()
}

// fallbackListener serves a TCP+TLS fallback listener: accept, complete
// the TLS 1.3 handshake, and hold the connection. The mux exchanges no
// frames at dial time, so a completed handshake is all a dial needs.
func fallbackListener(t *testing.T, pki *testPKI) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		NextProtos:   []string{fallback.ALPN},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_ = c.(*tls.Conn).Handshake()
				// Hold; the test closes the client side.
			}(c)
		}
	}()
	return ln
}

// quicListen serves a live idyl/2 QUIC listener for the healthy-path test.
func quicListen(pki *testPKI) (*quic.Listener, error) {
	return quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		NextProtos:   []string{"idyl/2"},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{})
}

// TestDialTransportBudgetRetainsFallbackShare: the QUIC leg's slice
// derives from the caller's dial budget, so the fallback attempt always
// retains a share. If a budget at or below FallbackThreshold gave the
// whole window to the QUIC attempt, its timeout would coincide with the
// caller's own deadline and dialTransport would return the QUIC error
// without ever dialing the fallback: budget arithmetic would silently
// disable a configured transport.
func TestDialTransportBudgetRetainsFallbackShare(t *testing.T) {
	pki := newTestPKI(t)
	ln := fallbackListener(t, pki)

	cfg := pki.clientConfig()
	cfg.Endpoint = deadQUICEndpoint(t) // QUIC fails by silence only
	cfg.FallbackEndpoint = ln.Addr().String()
	// FallbackThreshold is left zero: the 3 s default exceeds the caller's
	// 2 s budget below, the case in which an unclamped QUIC slice would
	// leave nothing for the fallback.

	budget := 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), budget)
	defer cancel()

	t0 := time.Now()
	conn, transport, err := dialTransport(ctx, cfg, 15*time.Second)
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("dial budget %s (threshold default 3s) returned only %v after %s; the QUIC attempt consumed the fallback share of the budget",
			budget, err, elapsed.Round(time.Millisecond))
	}
	defer func() { _ = conn.CloseWithError(0, "done") }()
	if transport != wire.TransportTCPFallback {
		t.Fatalf("landed on %q, want %q", transport, wire.TransportTCPFallback)
	}
	if elapsed > budget {
		t.Fatalf("selection took %s, past the caller's %s budget", elapsed.Round(time.Millisecond), budget)
	}
}

// Without a caller deadline the configured threshold is the QUIC slice;
// the clamp engages only when a budget exists to derive from.
func TestDialTransportUnboundedBudgetKeepsConfiguredThreshold(t *testing.T) {
	pki := newTestPKI(t)
	ln := fallbackListener(t, pki)

	cfg := pki.clientConfig()
	cfg.Endpoint = deadQUICEndpoint(t)
	cfg.FallbackEndpoint = ln.Addr().String()
	cfg.FallbackThreshold = 300 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background()) // no deadline
	defer cancel()

	t0 := time.Now()
	conn, transport, err := dialTransport(ctx, cfg, 15*time.Second)
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("dialTransport: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "done") }()
	if transport != wire.TransportTCPFallback {
		t.Fatalf("landed on %q, want %q", transport, wire.TransportTCPFallback)
	}
	if elapsed < cfg.FallbackThreshold {
		t.Fatalf("fallback landed at %s, before the %s QUIC slice elapsed; the QUIC attempt was cut short with no caller budget in play",
			elapsed.Round(time.Millisecond), cfg.FallbackThreshold)
	}
}

// A healthy QUIC path wins the race. This is the default selection, and
// the test ensures the budget clamp never moves a live QUIC edge to the
// fallback. The generous threshold keeps loopback handshakes slowed by the
// race detector from deciding the outcome on timing.
func TestDialTransportHealthyQuicWins(t *testing.T) {
	pki := newTestPKI(t)
	qln, err := quicListen(pki)
	if err != nil {
		t.Fatalf("quic listen: %v", err)
	}
	defer func() { _ = qln.Close() }()
	ln := fallbackListener(t, pki)

	cfg := pki.clientConfig()
	cfg.Endpoint = qln.Addr().String()
	cfg.FallbackEndpoint = ln.Addr().String()
	cfg.FallbackThreshold = 30 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	conn, transport, err := dialTransport(ctx, cfg, 15*time.Second)
	if err != nil {
		t.Fatalf("dialTransport: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "done") }()
	if transport != wire.TransportQUIC {
		t.Fatalf("landed on %q, want %q", transport, wire.TransportQUIC)
	}
}

// ForceFallback skips QUIC entirely: no time is spent on the dead QUIC
// endpoint.
func TestDialTransportForceFallbackSkipsQuic(t *testing.T) {
	pki := newTestPKI(t)
	ln := fallbackListener(t, pki)

	cfg := pki.clientConfig()
	cfg.Endpoint = deadQUICEndpoint(t)
	cfg.FallbackEndpoint = ln.Addr().String()
	cfg.ForceFallback = true

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t0 := time.Now()
	conn, transport, err := dialTransport(ctx, cfg, 15*time.Second)
	elapsed := time.Since(t0)
	if err != nil {
		t.Fatalf("dialTransport: %v", err)
	}
	defer func() { _ = conn.CloseWithError(0, "done") }()
	if transport != wire.TransportTCPFallback {
		t.Fatalf("landed on %q, want %q", transport, wire.TransportTCPFallback)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("ForceFallback took %s; time was spent on QUIC although it was skipped", elapsed.Round(time.Millisecond))
	}
}

// A caller that cancels mid-race gets an error back: genuine budget
// exhaustion, distinct from the deadline coincidence the clamp prevents.
func TestDialTransportCallerCancelReportsQuicError(t *testing.T) {
	pki := newTestPKI(t)
	ln := fallbackListener(t, pki)

	cfg := pki.clientConfig()
	cfg.Endpoint = deadQUICEndpoint(t)
	cfg.FallbackEndpoint = ln.Addr().String()
	cfg.FallbackThreshold = 30 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()

	conn, _, err := dialTransport(ctx, cfg, 15*time.Second)
	if err == nil {
		_ = conn.CloseWithError(0, "unexpected")
		t.Fatal("dialTransport succeeded after the caller canceled mid-race")
	}
}
