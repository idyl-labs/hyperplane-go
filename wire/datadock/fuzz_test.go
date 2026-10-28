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

package datadock

import (
	"bytes"
	"errors"
	"testing"
)

// FuzzDecodeHeader checks the header decoder on arbitrary bytes. It must
// never panic, every refusal wraps ErrMalformed, and a header it accepts
// re-encodes to exactly the bytes it was decoded from.
func FuzzDecodeHeader(f *testing.F) {
	for _, raw := range goldens(f) {
		f.Add(raw)
	}
	f.Add([]byte{})
	f.Add(make([]byte, HeaderBytes))
	f.Fuzz(func(t *testing.T, raw []byte) {
		header, err := DecodeHeader(raw)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("refusal %v does not wrap ErrMalformed", err)
			}
			return
		}
		encoded, err := header.Encode()
		if err != nil {
			t.Fatalf("accepted header %+v does not encode: %v", header, err)
		}
		if !bytes.Equal(encoded, raw) {
			t.Fatalf("accepted %x re-encodes to %x", raw, encoded)
		}
	})
}

// FuzzReadReply checks the reply reader on arbitrary bytes. It must never
// panic or read past the reply, and a reply it accepts re-encodes to
// exactly the bytes it consumed.
func FuzzReadReply(f *testing.F) {
	for _, raw := range goldens(f) {
		f.Add(raw)
	}
	f.Add([]byte{})
	f.Add([]byte{200, 3, 'n', 'e', 'w', 0x16, 0x03})
	f.Fuzz(func(t *testing.T, raw []byte) {
		stream := bytes.NewReader(raw)
		reply, err := ReadReply(stream)
		if err != nil {
			return
		}
		consumed := raw[:len(raw)-stream.Len()]
		if len(consumed) != 2+len(reply.Reason) {
			t.Fatalf("read %d bytes for a reply with a %d-byte reason", len(consumed), len(reply.Reason))
		}
		encoded, err := reply.Encode()
		if err != nil {
			t.Fatalf("accepted reply %+v does not encode: %v", reply, err)
		}
		if !bytes.Equal(encoded, consumed) {
			t.Fatalf("accepted %x re-encodes to %x", consumed, encoded)
		}
	})
}
