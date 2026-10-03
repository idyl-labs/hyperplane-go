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

// codec.go: the canonical transport names.

// Transport names identify the transport a dock rides: native QUIC, or the
// TCP+TLS fallback transport in package wire/fallback. These strings are
// the canonical values the client reports for a dock's transport.
const (
	TransportQUIC        = "quic"
	TransportTCPFallback = "tcp-fallback"
)
