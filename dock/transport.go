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
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"

	"github.com/idyl-labs/hyperplane-go/wire"
	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

// The client side of the dock transport. QUIC is the primary transport;
// the TCP+TLS fallback serves networks that block UDP, with fewer
// properties (no datagrams, no connection migration, head-of-line
// blocking). Selection is automatic: the QUIC attempt gets a bounded
// window, because blocked UDP fails by silence, and the fallback is dialed
// only when QUIC could not establish a connection. A typed refusal from
// the edge, such as ErrOverloaded, is an answer rather than a blocked
// network and never triggers the fallback.

// transportStream is the bidirectional stream surface the dock protocol
// uses on either transport.
type transportStream interface {
	io.Reader
	io.Writer
	Close() error
	CancelRead(code uint64)
	CancelWrite(code uint64)
	SetReadDeadline(t time.Time) error
}

// transportReceiveStream is the receive side of an edge-opened
// unidirectional stream (an event push). It carries cancel and deadline
// methods so a consumer can drain the stream to EOF, with a bound, after
// the payload frame; that read retires the stream and returns its credit
// to the edge.
type transportReceiveStream interface {
	io.Reader
	CancelRead(code uint64)
	SetReadDeadline(t time.Time) error
}

// transportConn is one dock-side connection on either transport.
type transportConn interface {
	OpenStreamSync(ctx context.Context) (transportStream, error)
	AcceptStream(ctx context.Context) (transportStream, error)
	AcceptUniStream(ctx context.Context) (transportReceiveStream, error)
	// SendKeepalive emits one unit of transport activity (a datagram on
	// QUIC, a PING frame on the fallback mux).
	SendKeepalive() error
	CloseWithError(code uint64, reason string) error
	Context() context.Context
	Resumed() bool
	ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error)
}

// ---------------------------------------------------------------------------
// QUIC
// ---------------------------------------------------------------------------

type quicTransportConn struct{ conn *quic.Conn }

func (q quicTransportConn) OpenStreamSync(ctx context.Context) (transportStream, error) {
	s, err := q.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return quicTransportStream{s}, nil
}

func (q quicTransportConn) AcceptStream(ctx context.Context) (transportStream, error) {
	s, err := q.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return quicTransportStream{s}, nil
}

func (q quicTransportConn) AcceptUniStream(ctx context.Context) (transportReceiveStream, error) {
	s, err := q.conn.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	return quicReceiveStream{s}, nil
}

// quicReceiveStream adapts *quic.ReceiveStream's typed CancelRead to the
// uint64 code the dock protocol speaks (Read and SetReadDeadline pass through).
type quicReceiveStream struct{ *quic.ReceiveStream }

func (s quicReceiveStream) CancelRead(code uint64) {
	s.ReceiveStream.CancelRead(quic.StreamErrorCode(code))
}

func (q quicTransportConn) SendKeepalive() error {
	// The keepalive datagram is the single byte 0x00. The wire package
	// defines it so that client and codec agree on the form.
	return q.conn.SendDatagram(wire.LaneKeepalive())
}

func (q quicTransportConn) CloseWithError(code uint64, reason string) error {
	return q.conn.CloseWithError(quic.ApplicationErrorCode(code), reason)
}

func (q quicTransportConn) Context() context.Context { return q.conn.Context() }

func (q quicTransportConn) Resumed() bool { return q.conn.ConnectionState().TLS.DidResume }

func (q quicTransportConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	state := q.conn.ConnectionState().TLS
	return state.ExportKeyingMaterial(label, context, length)
}

type quicTransportStream struct{ *quic.Stream }

func (s quicTransportStream) CancelRead(code uint64) {
	s.Stream.CancelRead(quic.StreamErrorCode(code))
}

func (s quicTransportStream) CancelWrite(code uint64) {
	s.Stream.CancelWrite(quic.StreamErrorCode(code))
}

// ---------------------------------------------------------------------------
// TCP+TLS fallback
// ---------------------------------------------------------------------------

type fallbackTransportConn struct {
	conn *fallback.Conn
	tls  tls.ConnectionState
	raw  net.Conn
}

func (f *fallbackTransportConn) OpenStreamSync(ctx context.Context) (transportStream, error) {
	return f.conn.OpenStreamSync(ctx)
}

func (f *fallbackTransportConn) AcceptStream(ctx context.Context) (transportStream, error) {
	return f.conn.AcceptStream(ctx)
}

func (f *fallbackTransportConn) AcceptUniStream(ctx context.Context) (transportReceiveStream, error) {
	return f.conn.AcceptUniStream(ctx)
}

func (f *fallbackTransportConn) SendKeepalive() error { return f.conn.SendKeepalive() }

func (f *fallbackTransportConn) CloseWithError(code uint64, reason string) error {
	return f.conn.CloseWithError(code, reason)
}

func (f *fallbackTransportConn) Context() context.Context { return f.conn.Context() }

func (f *fallbackTransportConn) Resumed() bool { return f.tls.DidResume }

func (f *fallbackTransportConn) ExportKeyingMaterial(label string, context []byte, length int) ([]byte, error) {
	return f.tls.ExportKeyingMaterial(label, context, length)
}

// ---------------------------------------------------------------------------
// Dialing and selection
// ---------------------------------------------------------------------------

// quicALPNOffer is the client's QUIC ALPN offer: exactly idyl/2. It is
// not a Config field, because the protocols a client speaks are fixed by
// this package, not chosen by the caller.
var quicALPNOffer = []string{"idyl/2"}

func clientTLS(cfg Config, alpn ...string) (*tls.Config, error) {
	if len(alpn) == 0 {
		return nil, errors.New("dock: no ALPN offered")
	}
	if cfg.ServerID.IsZero() {
		return nil, errors.New("dock: ServerID is required")
	}
	if cfg.Bundles == nil {
		return nil, errors.New("dock: Bundles is required")
	}
	if len(cfg.SVID.Certificate) == 0 || cfg.SVID.PrivateKey == nil {
		return nil, errors.New("dock: SVID certificate and key are required")
	}
	conf := tlsconfig.TLSClientConfig(cfg.Bundles, tlsconfig.AuthorizeID(cfg.ServerID))
	conf.Certificates = []tls.Certificate{cfg.SVID}
	conf.NextProtos = alpn
	conf.MinVersion = tls.VersionTLS13
	conf.ClientSessionCache = cfg.SessionCache
	return conf, nil
}

// Default QUIC receive-window ceilings, matching the edge's defaults so
// that a dock and its edge allow the same throughput for large transfers.
// A window bounds only buffered, unread data, so its memory cost is per
// active transfer, not per idle dock.
const (
	defaultMaxStreamReceiveWindow     = 16 << 20 // 16 MiB per stream
	defaultMaxConnectionReceiveWindow = 64 << 20 // 64 MiB per dock connection
)

// quicConfig is the dock's QUIC configuration: the keepalive cadence, the
// flow-control ceilings and the inbound stream bound.
func quicConfig(cfg Config, keepalive time.Duration) *quic.Config {
	streamWin := cfg.MaxStreamReceiveWindow
	if streamWin == 0 {
		streamWin = defaultMaxStreamReceiveWindow
	}
	connWin := cfg.MaxConnectionReceiveWindow
	if connWin == 0 {
		connWin = defaultMaxConnectionReceiveWindow
	}
	quicConf := &quic.Config{
		KeepAlivePeriod: keepalive,
		MaxIdleTimeout:  3 * keepalive,
		EnableDatagrams: true,
		// These raise the flow-control ceilings only: quic-go grows its
		// windows from small initial values toward these maxima as a
		// stream's bandwidth-delay product requires, so the ceilings
		// matter on long or fast paths and rarely on a local one.
		MaxStreamReceiveWindow:     streamWin,
		MaxConnectionReceiveWindow: connWin,
	}
	if cfg.DisableKeepalive {
		quicConf.KeepAlivePeriod = 0
	}
	if cfg.MaxIncomingStreams > 0 {
		quicConf.MaxIncomingStreams = cfg.MaxIncomingStreams
	}
	return quicConf
}

func dialQUIC(ctx context.Context, cfg Config, keepalive time.Duration) (transportConn, error) {
	quicConf := quicConfig(cfg, keepalive)
	tlsConf, err := clientTLS(cfg, quicALPNOffer...)
	if err != nil {
		return nil, err
	}
	if cfg.LocalIP == "" {
		conn, err := quic.DialAddr(ctx, cfg.Endpoint, tlsConf, quicConf)
		if err != nil {
			return nil, fmt.Errorf("dock: dial: %w", err)
		}
		return quicTransportConn{conn}, nil
	}

	// Source-bound dial: a fresh per-dock socket on the named local IP.
	// The socket lives exactly as long as the dock's connection.
	ip := net.ParseIP(cfg.LocalIP)
	if ip == nil {
		return nil, fmt.Errorf("dock: LocalIP %q is not an IP address", cfg.LocalIP)
	}
	raddr, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("dock: dial: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: ip})
	if err != nil {
		return nil, fmt.Errorf("dock: bind %s: %w", cfg.LocalIP, err)
	}
	tr := &quic.Transport{Conn: udpConn}
	conn, err := tr.Dial(ctx, raddr, tlsConf, quicConf)
	if err != nil {
		_ = tr.Close()
		_ = udpConn.Close()
		return nil, fmt.Errorf("dock: dial: %w", err)
	}
	go func() {
		<-conn.Context().Done()
		_ = tr.Close()
		_ = udpConn.Close()
	}()
	return quicTransportConn{conn}, nil
}

func dialFallback(ctx context.Context, cfg Config, keepalive time.Duration) (transportConn, error) {
	endpoint := cfg.FallbackEndpoint
	if endpoint == "" {
		endpoint = cfg.Endpoint
	}
	var d net.Dialer
	if cfg.LocalIP != "" {
		ip := net.ParseIP(cfg.LocalIP)
		if ip == nil {
			return nil, fmt.Errorf("dock: LocalIP %q is not an IP address", cfg.LocalIP)
		}
		d.LocalAddr = &net.TCPAddr{IP: ip}
	}
	raw, err := d.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("dock: fallback dial: %w", err)
	}
	tlsConf, err := clientTLS(cfg, fallback.ALPN)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	tc := tls.Client(raw, tlsConf)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("dock: fallback handshake: %w", err)
	}
	idle := 3 * keepalive
	if cfg.DisableKeepalive {
		idle = 0 // DisableKeepalive also turns off the client's own idle detection
	}
	return &fallbackTransportConn{
		conn: fallback.Client(tc, idle),
		tls:  tc.ConnectionState(),
		raw:  raw,
	}, nil
}

// dialTransport selects the transport: QUIC within a bounded window, then
// the fallback if QUIC could not connect. ForceFallback skips QUIC. It
// returns the connection and the transport name it used.
func dialTransport(ctx context.Context, cfg Config, keepalive time.Duration) (transportConn, string, error) {
	if cfg.ForceFallback {
		conn, err := dialFallback(ctx, cfg, keepalive)
		return conn, wire.TransportTCPFallback, err
	}

	threshold := cfg.FallbackThreshold
	if threshold == 0 {
		threshold = 3 * time.Second
	}
	// The QUIC window is taken from the caller's own budget: with a
	// deadline, QUIC may spend at most half of what remains, so the
	// fallback attempt always keeps a share. Without this clamp, a budget
	// at or below the threshold would give the whole window to QUIC; its
	// timeout would then coincide with the caller's deadline, the
	// ctx.Err() check below would fire, and the fallback would never be
	// dialed.
	if dl, ok := ctx.Deadline(); ok {
		if half := time.Until(dl) / 2; half < threshold {
			threshold = half
		}
	}
	qctx, cancel := context.WithTimeout(ctx, threshold)
	conn, qerr := dialQUIC(qctx, cfg, keepalive)
	cancel()
	if qerr == nil {
		return conn, wire.TransportQUIC, nil
	}
	if ctx.Err() != nil {
		return nil, "", qerr // the caller's context ended; report QUIC's failure
	}

	fconn, ferr := dialFallback(ctx, cfg, keepalive)
	if ferr != nil {
		return nil, "", errors.Join(qerr, ferr)
	}
	return fconn, wire.TransportTCPFallback, nil
}
