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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

// The QUIC ALPN offer is a fixed protocol identifier, not a preference
// list: exactly idyl/2 and nothing else. There is no other QUIC protocol
// for the client to fall back to.
func TestQUICALPNOfferPinned(t *testing.T) {
	want := []string{"idyl/2"}
	if len(quicALPNOffer) != len(want) {
		t.Fatalf("quicALPNOffer = %v, want %v", quicALPNOffer, want)
	}
	for i := range want {
		if quicALPNOffer[i] != want[i] {
			t.Fatalf("quicALPNOffer = %v, want %v", quicALPNOffer, want)
		}
	}
}

func TestClientTLSPropagatesOffer(t *testing.T) {
	pki := newTestPKI(t)
	cfg := pki.clientConfig()

	conf, err := clientTLS(cfg, quicALPNOffer...)
	if err != nil {
		t.Fatalf("clientTLS: %v", err)
	}
	if len(conf.NextProtos) != 1 || conf.NextProtos[0] != "idyl/2" {
		t.Fatalf("NextProtos = %v, want [idyl/2]", conf.NextProtos)
	}
	if conf.MinVersion != tls.VersionTLS13 {
		t.Fatalf("MinVersion = %x, want TLS 1.3", conf.MinVersion)
	}

	// The TCP fallback offers its own single ALPN; the QUIC offer list
	// does not apply to it.
	fconf, err := clientTLS(cfg, fallback.ALPN)
	if err != nil {
		t.Fatalf("clientTLS(fallback): %v", err)
	}
	if len(fconf.NextProtos) != 1 || fconf.NextProtos[0] != fallback.ALPN {
		t.Fatalf("fallback NextProtos = %v, want [%s]", fconf.NextProtos, fallback.ALPN)
	}
}

// The QUIC offer over a real TLS 1.3 handshake: a server speaking idyl/2
// negotiates it, and a server that speaks only other protocols refuses the
// handshake for lack of a shared protocol. Without the refusal cases the
// positive case could not distinguish a selected protocol from an ignored
// ALPN extension.
func TestALPNServerSelects(t *testing.T) {
	pki := newTestPKI(t)

	cases := []struct {
		name        string
		serverALPNs []string
		want        string // negotiated; "" = handshake must fail
	}{
		{"edge offering idyl/2 is selected", []string{"idyl/2"}, "idyl/2"},
		{"edge offering only idyl/1 is refused in the handshake", []string{"idyl/1"}, ""},
		{"no overlap refused", []string{"other/9"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clientConf, err := clientTLS(pki.clientConfig(), quicALPNOffer...)
			if err != nil {
				t.Fatalf("clientTLS: %v", err)
			}
			serverConf := &tls.Config{
				Certificates: []tls.Certificate{pki.serverCert},
				NextProtos:   tc.serverALPNs,
				MinVersion:   tls.VersionTLS13,
			}

			cc, sc := net.Pipe()
			defer func() { _ = cc.Close() }()
			defer func() { _ = sc.Close() }()
			server := tls.Server(sc, serverConf)
			serverErr := make(chan error, 1)
			go func() { serverErr <- server.Handshake() }()

			client := tls.Client(cc, clientConf)
			err = client.Handshake()
			if tc.want == "" {
				if err == nil {
					t.Fatalf("handshake succeeded (negotiated %q), want ALPN refusal",
						client.ConnectionState().NegotiatedProtocol)
				}
				return
			}
			if err != nil {
				t.Fatalf("client handshake: %v", err)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("server handshake: %v", err)
			}
			if got := client.ConnectionState().NegotiatedProtocol; got != tc.want {
				t.Fatalf("negotiated %q, want %q", got, tc.want)
			}
		})
	}
}

// dialFallback over a real TLS 1.3 handshake. The edge checks the fallback
// ALPN exactly, so a wrong offer would refuse every fallback dock; this test
// is what makes such a change fail. Positive: a listener speaking exactly
// idyl-fallback/1 admits the dial and negotiates it. Negative: a listener
// speaking anything else refuses it during the handshake.
func TestDialFallbackOffersFallbackALPN(t *testing.T) {
	pki := newTestPKI(t)
	listen := func(t *testing.T, alpns []string) (net.Listener, chan string) {
		t.Helper()
		ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
			Certificates: []tls.Certificate{pki.serverCert},
			NextProtos:   alpns,
			MinVersion:   tls.VersionTLS13,
		})
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		negotiated := make(chan string, 4)
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					tc := c.(*tls.Conn)
					if err := tc.Handshake(); err != nil {
						_ = tc.Close()
						return
					}
					negotiated <- tc.ConnectionState().NegotiatedProtocol
					// Hold the conn; the test closes the client side.
				}(c)
			}
		}()
		return ln, negotiated
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	t.Run("admitted by an idyl-fallback/1 listener", func(t *testing.T) {
		ln, negotiated := listen(t, []string{fallback.ALPN})
		cfg := pki.clientConfig()
		cfg.Endpoint = ln.Addr().String()
		conn, err := dialFallback(ctx, cfg, 15*time.Second)
		if err != nil {
			t.Fatalf("dialFallback against an idyl-fallback/1 listener: %v", err)
		}
		defer func() { _ = conn.CloseWithError(0, "done") }()
		select {
		case got := <-negotiated:
			if got != fallback.ALPN {
				t.Fatalf("server negotiated %q, want %q", got, fallback.ALPN)
			}
		case <-ctx.Done():
			t.Fatal("server never completed the handshake")
		}
	})

	t.Run("refused by a listener without idyl-fallback/1", func(t *testing.T) {
		ln, _ := listen(t, []string{"idyl/2"})
		cfg := pki.clientConfig()
		cfg.Endpoint = ln.Addr().String()
		if conn, err := dialFallback(ctx, cfg, 15*time.Second); err == nil {
			_ = conn.CloseWithError(0, "unexpected")
			t.Fatal("dialFallback succeeded against a listener not speaking idyl-fallback/1; the offer must be refused in-handshake")
		}
	})
}

// testPKI is the minimal SPIFFE-shaped material clientTLS needs: a CA
// authority for the bundle, a server SVID (one URI SAN and no DNS names,
// the shape stock hostname verification refuses), and a client SVID
// certificate. Ed25519 throughout.
type testPKI struct {
	td         spiffeid.TrustDomain
	serverID   spiffeid.ID
	bundles    x509bundle.Source
	serverCert tls.Certificate
	clientCert tls.Certificate
}

func (p *testPKI) clientConfig() Config {
	return Config{
		ServerID: p.serverID,
		Bundles:  p.bundles,
		SVID:     p.clientCert,
	}
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	td := spiffeid.RequireTrustDomainFromString("alpn-test.example")
	serverID := spiffeid.RequireFromPath(td, "/fabric/edge")

	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "alpn-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, caPub, caKey)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}

	leaf := func(uri *url.URL, serial int64) tls.Certificate {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("leaf key: %v", err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			URIs:         []*url.URL{uri},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, pub, caKey)
		if err != nil {
			t.Fatalf("leaf cert: %v", err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}

	return &testPKI{
		td:         td,
		serverID:   serverID,
		bundles:    x509bundle.FromX509Authorities(td, []*x509.Certificate{ca}),
		serverCert: leaf(serverID.URL(), 2),
		clientCert: leaf(spiffeid.RequireFromPath(td, "/client").URL(), 3),
	}
}
