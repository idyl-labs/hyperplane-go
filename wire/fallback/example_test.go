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
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/idyl-labs/hyperplane-go/wire/fallback"
)

// A client and a server exchange bytes over one bidirectional stream. In
// production each side wraps a TLS 1.3 connection negotiated with
// fallback.ALPN; net.Pipe stands in for it here.
func Example() {
	clientEnd, serverEnd := net.Pipe()
	client := fallback.Client(clientEnd, 0)
	server := fallback.Server(serverEnd, 0)
	ctx := context.Background()

	// The server echoes each request back with a prefix, then half-closes.
	go func() {
		s, err := server.AcceptStream(ctx)
		if err != nil {
			return
		}
		req, err := io.ReadAll(s)
		if err != nil {
			return
		}
		_, _ = s.Write(append([]byte("echo: "), req...))
		_ = s.Close()
	}()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		fmt.Println("write:", err)
		return
	}
	_ = s.Close() // half-close: the server reads EOF, the reply still arrives
	reply, err := io.ReadAll(s)
	if err != nil {
		fmt.Println("read:", err)
		return
	}
	fmt.Println(string(reply))

	_ = client.CloseWithError(0, "done")
	_ = server.CloseWithError(0, "done")
	// Output: echo: hello
}

// Closing a connection with an application code lets the peer classify
// the close from its connection context.
func ExampleConn_CloseWithError() {
	clientEnd, serverEnd := net.Pipe()
	client := fallback.Client(clientEnd, 0)
	server := fallback.Server(serverEnd, 0)

	_ = client.CloseWithError(0x10, "draining")

	<-server.Context().Done()
	var ce *fallback.ConnError
	if errors.As(context.Cause(server.Context()), &ce) {
		fmt.Printf("code=%#x reason=%q remote=%t\n", ce.Code, ce.Reason, ce.Remote)
	}
	// Output: code=0x10 reason="draining" remote=true
}

// Canceling a stream sends a RESET carrying an application code, which
// the peer reads as a typed StreamResetError.
func ExampleStream_CancelWrite() {
	clientEnd, serverEnd := net.Pipe()
	client := fallback.Client(clientEnd, 0)
	server := fallback.Server(serverEnd, 0)
	ctx := context.Background()

	s, err := client.OpenStreamSync(ctx)
	if err != nil {
		fmt.Println("open:", err)
		return
	}
	s.CancelWrite(42)

	peer, err := server.AcceptStream(ctx)
	if err != nil {
		fmt.Println("accept:", err)
		return
	}
	_, err = peer.Read(make([]byte, 1))
	var reset fallback.StreamResetError
	if errors.As(err, &reset) {
		fmt.Printf("reset code=%d remote=%t\n", reset.Code, reset.Remote)
	}
	fmt.Println(errors.Is(err, fallback.ErrStreamReset))

	_ = client.CloseWithError(0, "done")
	_ = server.CloseWithError(0, "done")
	// Output:
	// reset code=42 remote=true
	// true
}
