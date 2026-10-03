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

// Package dockv3 defines the dock/3 control-stream messages exchanged
// between a client and the edge on a dock's control channel:
// ClientToEdge, which carries the client's DockHello, and EdgeToClient,
// which carries the edge's welcome, drain, overload, and lane attach and
// close notices.
//
// A DockHello always carries admission material: the exact
// ZoneAdmissionLease envelope, the canonical dock-proof input bound to the
// connection's TLS exporter, and an Ed25519 signature over that input made
// with the client's SVID key.
package dockv3

// Contract is the dock protocol identifier carried in every DockHello and
// bound into every dock proof.
const Contract = "dock/3"
