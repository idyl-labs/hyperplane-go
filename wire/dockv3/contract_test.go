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

package dockv3_test

import (
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/idyl-labs/hyperplane-go/wire/admissionv3"
	"github.com/idyl-labs/hyperplane-go/wire/dockv3"
)

// TestContract pins the dock protocol identifier. Every DockHello carries
// it and every dock proof binds to it, so it is a wire value.
func TestContract(t *testing.T) {
	if dockv3.Contract != "dock/3" {
		t.Fatalf("Contract = %q, want %q", dockv3.Contract, "dock/3")
	}
}

// TestContractAgreesWithAdmission checks that the protocol named in a
// hello is the protocol a dock proof binds to, as admissionv3 states it.
func TestContractAgreesWithAdmission(t *testing.T) {
	if dockv3.Contract != admissionv3.DockContract {
		t.Fatalf("dockv3.Contract %q != admissionv3.DockContract %q", dockv3.Contract, admissionv3.DockContract)
	}
}

// TestControlStreamOneofsCarryOneMessage checks that each control-stream
// frame carries exactly one message: setting a second member of the oneof
// replaces the first, so a frame can never be read as two messages.
func TestControlStreamOneofsCarryOneMessage(t *testing.T) {
	frame := &dockv3.EdgeToClient{Msg: &dockv3.EdgeToClient_Welcome{Welcome: &dockv3.DockWelcome{}}}
	frame.Msg = &dockv3.EdgeToClient_Drain{Drain: &dockv3.DockDrain{}}
	encoded, err := proto.Marshal(frame)
	if err != nil {
		t.Fatal(err)
	}
	var decoded dockv3.EdgeToClient
	if err := proto.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetWelcome() != nil || decoded.GetDrain() == nil {
		t.Fatalf("decoded frame carries %T", decoded.GetMsg())
	}
	hello := &dockv3.ClientToEdge{Msg: &dockv3.ClientToEdge_Hello{Hello: &dockv3.DockHello{Contract: dockv3.Contract}}}
	if hello.GetHello().GetContract() != "dock/3" {
		t.Fatal("hello does not carry the contract")
	}
}
