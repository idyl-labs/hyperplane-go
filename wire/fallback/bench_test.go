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

package fallback

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
)

// benchPair returns a connected client and server Conn over loopback TCP,
// the transport fallback/1 runs on, without TLS.
func benchPair(b *testing.B) (*Conn, *Conn) {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- nc
	}()
	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	sc, ok := <-accepted
	if !ok {
		b.Fatal("accept failed")
	}
	client, server := Client(cc, 0), Server(sc, 0)
	b.Cleanup(func() {
		_ = client.CloseWithError(0, "bench done")
		_ = server.CloseWithError(0, "bench done")
	})
	return client, server
}

// BenchmarkStreamThroughput measures one stream carrying writes of several
// sizes from client to server under credit-based flow control, with the
// server consuming as fast as it can.
func BenchmarkStreamThroughput(b *testing.B) {
	for _, size := range []int{1 << 10, 16 << 10, MaxFramePayload, 1 << 20} {
		b.Run(fmt.Sprintf("%dKiB", size>>10), func(b *testing.B) {
			client, server := benchPair(b)
			ctx := context.Background()
			cs, err := client.OpenStreamSync(ctx)
			if err != nil {
				b.Fatal(err)
			}
			received := make(chan int64, 1)
			go func() {
				ss, err := server.AcceptStream(ctx)
				if err != nil {
					received <- -1
					return
				}
				n, _ := io.Copy(io.Discard, ss)
				received <- n
			}()

			buf := make([]byte, size)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			var sent int64
			for b.Loop() {
				if _, err := cs.Write(buf); err != nil {
					b.Fatal(err)
				}
				sent += int64(size)
			}
			if err := cs.Close(); err != nil {
				b.Fatal(err)
			}
			if got := <-received; got != sent {
				b.Fatalf("server received %d bytes, client sent %d", got, sent)
			}
		})
	}
}

// BenchmarkStreamOpenClose measures the full life of a stream: the client
// opens it and half-closes, the server accepts and half-closes back, and
// the client reads the FIN, after which both sides release it.
func BenchmarkStreamOpenClose(b *testing.B) {
	client, server := benchPair(b)
	ctx := context.Background()
	go func() {
		for {
			ss, err := server.AcceptStream(ctx)
			if err != nil {
				return
			}
			_ = ss.Close()
		}
	}()

	one := make([]byte, 1)
	b.ReportAllocs()
	for b.Loop() {
		cs, err := client.OpenStreamSync(ctx)
		if err != nil {
			b.Fatal(err)
		}
		if err := cs.Close(); err != nil {
			b.Fatal(err)
		}
		if _, err := cs.Read(one); !errors.Is(err, io.EOF) {
			b.Fatalf("Read = %v, want io.EOF", err)
		}
	}
}
