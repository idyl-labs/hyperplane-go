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
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// The edge opens every inbound lane stream toward the dock, so the dock's
// QUIC stream bound is the ceiling on its concurrent lane streams. The edge
// side sees that bound as the number of streams it may open.
func TestMaxIncomingStreamsBoundsTheEdgesOpens(t *testing.T) {
	pki := newTestPKI(t)
	ln, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{pki.serverCert},
		NextProtos:   []string{"idyl/2"},
		MinVersion:   tls.VersionTLS13,
	}, &quic.Config{})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	opens := func(t *testing.T, bound int64) int {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg := pki.clientConfig()
		cfg.Endpoint = ln.Addr().String()
		cfg.MaxIncomingStreams = bound
		conn, err := dialQUIC(ctx, cfg, 15*time.Second)
		if err != nil {
			t.Fatalf("dialQUIC: %v", err)
		}
		defer func() { _ = conn.CloseWithError(0, "done") }()
		edge, err := ln.Accept(ctx)
		if err != nil {
			t.Fatalf("accept: %v", err)
		}
		defer func() { _ = edge.CloseWithError(0, "done") }()
		n := 0
		for ; n < 1000; n++ {
			if _, err := edge.OpenStream(); err != nil {
				break
			}
		}
		return n
	}

	if got := opens(t, 0); got != 100 {
		t.Fatalf("default bound: the edge opened %d streams, want quic-go's 100", got)
	}
	if got := opens(t, 256); got != 256 {
		t.Fatalf("bound 256: the edge opened %d streams, want 256", got)
	}
}
