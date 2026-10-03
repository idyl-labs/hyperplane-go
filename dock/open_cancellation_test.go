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
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/idyl-labs/hyperplane-go/wire"
	dockpb "github.com/idyl-labs/hyperplane-go/wire/dockv2"
	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

type observedOpeningConn struct {
	net.Conn
	writes chan int32
	count  atomic.Int32
}

func (c *observedOpeningConn) Write(p []byte) (int, error) {
	n := c.count.Add(1)
	select {
	case c.writes <- n:
	default:
	}
	return c.Conn.Write(p)
}

// The real fallback mux must unblock even while its frame write mutex is held.
// net.Pipe provides deterministic backpressure without relying on TCP buffers.
func TestOpenCancellationInterruptsBlockedFallbackOpening(t *testing.T) {
	for _, phase := range []string{"stream open", "hello write", "welcome read"} {
		t.Run(phase, func(t *testing.T) {
			local, peer := net.Pipe()
			defer func() { _ = local.Close() }()
			defer func() { _ = peer.Close() }()
			observed := &observedOpeningConn{Conn: local, writes: make(chan int32, 8)}
			conn := &fallbackTransportConn{conn: fallback.Client(observed, 0), raw: local}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := make(chan error, 1)
			switch phase {
			case "stream open":
				go func() { <-observed.writes; ready <- nil }()
			case "hello write":
				go func() {
					// fallback/1's opening frame is its nine-byte header with no payload.
					_, err := io.ReadFull(peer, make([]byte, 9))
					if err != nil {
						ready <- err
						return
					}
					for n := range observed.writes {
						if n == 2 {
							ready <- nil
							return
						}
					}
				}()
			case "welcome read":
				server := fallback.Server(peer, 0)
				go func() {
					stream, err := server.AcceptStream(ctx)
					if err != nil {
						ready <- err
						return
					}
					var hello dockpb.ClientToEdge
					ready <- wire.ReadFrame(stream, &hello, 0)
				}()
			}
			done := make(chan error, 1)
			go func() {
				dock, err := openDock(ctx, Config{DisableKeepalive: true}, conn, wire.TransportTCPFallback, nil)
				if dock != nil {
					err = errors.New("canceled opening returned a dock")
				}
				done <- err
			}()
			select {
			case err := <-ready:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("opening did not reach blocked phase")
			}
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled opening succeeded")
				}
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation cause lost: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("cancellation did not drain opening")
			}
			if conn.Context().Err() == nil {
				t.Fatal("failed opening retained its connection")
			}
		})
	}
}

func TestOpenDeadlinePreservesContextCause(t *testing.T) {
	local, peer := net.Pipe()
	defer func() { _ = local.Close() }()
	defer func() { _ = peer.Close() }()
	conn := &fallbackTransportConn{conn: fallback.Client(local, 0), raw: local}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := openDock(ctx, Config{DisableKeepalive: true}, conn, wire.TransportTCPFallback, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("deadline cause lost: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("opening outlived its deadline")
	}
}

// Exercise the exported Open path over both authenticated transports, then
// require a new control frame to arrive after the setup context is canceled.
func TestReturnedDockSurvivesOpeningContextCancellation(t *testing.T) {
	for _, transport := range []string{"quic", "fallback"} {
		t.Run(transport, func(t *testing.T) {
			pki := newTestPKI(t)
			serverCtx, stopServer := context.WithTimeout(context.Background(), 5*time.Second)
			defer stopServer()
			accepted := make(chan transportConn, 1)
			serverError := make(chan error, 1)
			cfg := pki.clientConfig()
			cfg.DisableKeepalive = true
			if transport == "quic" {
				ln, err := quicListen(pki)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = ln.Close() }()
				cfg.Endpoint = ln.Addr().String()
				go func() {
					conn, err := ln.Accept(serverCtx)
					if err != nil {
						serverError <- err
						return
					}
					accepted <- quicTransportConn{conn}
				}()
			} else {
				ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
					Certificates: []tls.Certificate{pki.serverCert}, NextProtos: []string{fallback.ALPN}, MinVersion: tls.VersionTLS13,
				})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = ln.Close() }()
				cfg.Endpoint, cfg.ForceFallback = ln.Addr().String(), true
				go func() {
					raw, err := ln.Accept()
					if err != nil {
						serverError <- err
						return
					}
					if err := raw.(*tls.Conn).HandshakeContext(serverCtx); err != nil {
						_ = raw.Close()
						serverError <- err
						return
					}
					accepted <- &fallbackTransportConn{conn: fallback.Server(raw, 0), raw: raw}
				}()
			}
			proceed := make(chan struct{})
			received := make(chan struct{})
			go func() {
				var conn transportConn
				select {
				case conn = <-accepted:
				case <-serverCtx.Done():
					serverError <- serverCtx.Err()
					return
				}
				defer func() { _ = conn.CloseWithError(wire.DockCodeDrain, "test complete") }()
				stream, err := conn.AcceptStream(serverCtx)
				if err != nil {
					serverError <- err
					return
				}
				var hello dockpb.ClientToEdge
				if err := wire.ReadFrame(stream, &hello, 0); err != nil {
					serverError <- err
					return
				}
				if err := wire.WriteFrame(stream, welcomeFor(0)); err != nil {
					serverError <- err
					return
				}
				select {
				case <-proceed:
				case <-serverCtx.Done():
					serverError <- serverCtx.Err()
					return
				}
				serverError <- wire.WriteFrame(stream, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Drain{Drain: &dockpb.DockDrain{}}})
				select {
				case <-received:
				case <-serverCtx.Done():
				}
			}()
			openingCtx, cancelOpening := context.WithCancel(serverCtx)
			defer cancelOpening()
			dock, err := Open(openingCtx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = dock.Close() }()
			cancelOpening()
			close(proceed)
			select {
			case <-dock.Drained():
				close(received)
			case <-serverCtx.Done():
				t.Fatal("returned dock lost control channel after setup cancellation")
			}
			if err := <-serverError; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAbandonUnblocksFallbackWriteAndStreamAbort(t *testing.T) {
	local, peer := net.Pipe()
	defer func() { _ = local.Close() }()
	defer func() { _ = peer.Close() }()
	observed := &observedOpeningConn{Conn: local, writes: make(chan int32, 8)}
	conn := &fallbackTransportConn{conn: fallback.Client(observed, 0), raw: local}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	readOpening := make(chan error, 1)
	go func() { _, err := io.ReadFull(peer, make([]byte, 9)); readOpening <- err }()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-readOpening; err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() { _, err := stream.Write([]byte("blocked payload")); writeDone <- err }()
	for {
		select {
		case n := <-observed.writes:
			if n == 2 {
				goto blocked
			}
		case <-ctx.Done():
			t.Fatal("write did not reach transport")
		}
	}
blocked:
	abortDone := make(chan struct{})
	go func() { (&LaneStream{stream: stream}).Abort(); close(abortDone) }()
	_ = stream.SetReadDeadline(time.Now().Add(time.Second))
	_, err = stream.Read(make([]byte, 1))
	var reset fallback.StreamResetError
	if !errors.As(err, &reset) {
		t.Fatalf("stream abort did not reach local termination: %v", err)
	}
	select {
	case <-abortDone:
		t.Fatal("reset unexpectedly passed the blocked write")
	default:
	}
	abandonDone := make(chan error, 1)
	go func() { abandonDone <- (&Dock{conn: conn}).Abandon() }()
	select {
	case err := <-abandonDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("abandon waited for blocked transport write")
	}
	select {
	case err := <-writeDone:
		if err == nil {
			t.Fatal("abandoned transport write succeeded")
		}
	case <-ctx.Done():
		t.Fatal("abandon failed to release writer")
	}
	select {
	case <-abortDone:
	case <-ctx.Done():
		t.Fatal("abandon failed to release stream abort")
	}
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
		t.Fatal("abandoned connection remained live")
	}
}

func TestFailedOpeningDoesNotWaitForPeerToReadGracefulClose(t *testing.T) {
	for _, response := range []string{"missing welcome", "stream ended", "overloaded"} {
		t.Run(response, func(t *testing.T) {
			local, peer := net.Pipe()
			defer func() { _ = local.Close() }()
			defer func() { _ = peer.Close() }()
			conn := &fallbackTransportConn{conn: fallback.Client(local, 0), raw: local}
			peerDone := make(chan error, 1)
			go func() {
				// Read OPEN, the hello frame length and its protobuf payload.
				for range 3 {
					if _, err := readFallbackFrame(peer); err != nil {
						peerDone <- err
						return
					}
				}
				typ, windows := byte(0x03), 1
				payload := []byte{0, 0, 0, 0} // Empty protobuf has no Welcome.
				if response == "stream ended" {
					typ, payload, windows = 0x04, nil, 0
				}
				if response == "overloaded" {
					var encoded bytes.Buffer
					if err := wire.WriteFrame(&encoded, &dockpb.EdgeToClient{Msg: &dockpb.EdgeToClient_Overloaded{Overloaded: &dockpb.DockOverloaded{RetryAfterMs: 1000}}}); err != nil {
						peerDone <- err
						return
					}
					payload, windows = encoded.Bytes(), 2
				}
				frame := append([]byte{typ}, binary.BigEndian.AppendUint32(nil, 1)...)
				frame = binary.BigEndian.AppendUint32(frame, uint32(len(payload)))
				frame = append(frame, payload...)
				if _, err := peer.Write(frame); err != nil {
					peerDone <- err
					return
				}
				// Reading replenishes stream credit. Consume only those WINDOW
				// frames, then deliberately stop reading without closing TCP.
				for range windows {
					typ, err := readFallbackFrame(peer)
					if err != nil {
						peerDone <- err
						return
					}
					if typ != 0x06 {
						peerDone <- errors.New("expected credit update")
						return
					}
				}
				peerDone <- nil
			}()
			done := make(chan error, 1)
			go func() {
				dock, err := openDock(context.Background(), Config{DisableKeepalive: true}, conn, wire.TransportTCPFallback, nil)
				if dock != nil {
					err = errors.New("invalid welcome returned a dock")
				}
				done <- err
			}()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("invalid welcome accepted")
				}
				if response == "overloaded" {
					var over ErrOverloaded
					if !errors.As(err, &over) || over.RetryAfter != time.Second {
						t.Fatalf("lost typed refusal: %v", err)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("failed opening waited for peer to read close")
			}
			if err := <-peerDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func readFallbackFrame(r io.Reader) (byte, error) {
	var header [9]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, err
	}
	_, err := io.CopyN(io.Discard, r, int64(binary.BigEndian.Uint32(header[5:])))
	return header[0], err
}
