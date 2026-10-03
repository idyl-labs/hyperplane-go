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

package wire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
)

// frame.go: stream framing for protobuf-bearing byte streams, such as the
// dock control stream and the event and RPC preambles. One frame is a
// 4-byte big-endian length prefix followed by exactly that many bytes of
// marshaled message. The cap is the receiver's and is enforced before
// allocation, so a peer can never make the receiver allocate more than it
// agreed to buffer.

// ErrFrameTooLarge marks a frame whose declared length exceeds the
// receiver's cap.
var ErrFrameTooLarge = errors.New("wire: frame exceeds receiver cap")

// DefaultMaxFrame bounds control-plane frames. Dock control messages and
// verb preambles are small; 1 MiB leaves ample room for every legitimate
// frame. Because every legitimate frame is smaller than 16 MiB, the first
// byte of a length prefix is always 0x00, which lets a receiver tell a
// framed stream from one that begins with a nonzero stream kind byte.
const DefaultMaxFrame = 1 << 20

// WriteFrame marshals m and writes one length-prefixed frame.
func WriteFrame(w io.Writer, m proto.Message) error {
	b, err := proto.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > DefaultMaxFrame {
		return fmt.Errorf("%w: marshaled %d bytes", ErrFrameTooLarge, len(b))
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(b)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// WriteRawFrame writes one already-marshaled frame, such as a message
// produced by MarshalCanonical, whose exact bytes must be preserved.
func WriteRawFrame(w io.Writer, b []byte) error {
	if len(b) > DefaultMaxFrame {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(b))
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(b)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	_, err := w.Write(b)
	return err
}

// ReadRawFrame reads one length-prefixed frame's bytes, refusing frames
// past the cap (maxLen <= 0 means DefaultMaxFrame).
func ReadRawFrame(r io.Reader, maxLen int) ([]byte, error) {
	if maxLen <= 0 {
		maxLen = DefaultMaxFrame
	}
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if int(n) > maxLen {
		return nil, fmt.Errorf("%w: declared %d bytes, cap %d", ErrFrameTooLarge, n, maxLen)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

// ReadFrame reads one length-prefixed frame into m, refusing frames past
// the cap (maxLen <= 0 means DefaultMaxFrame).
func ReadFrame(r io.Reader, m proto.Message, maxLen int) error {
	b, err := ReadRawFrame(r, maxLen)
	if err != nil {
		return err
	}
	return proto.Unmarshal(b, m)
}
