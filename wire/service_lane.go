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

// NodeServiceLaneProfile names the negotiated profile for dock/3 Nodes to
// request STREAM lanes to exact authenticated Service principals. It changes
// no ordinary locator or endpoint admission contract and grants no authority
// by itself. A Service offers it on its own dock/2 connection; withdrawal and
// target selection always refer to that exact admitted connection generation.
const NodeServiceLaneProfile = "node-service-lanes/1"
