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
	"errors"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/idyl-labs/hyperplane-go/wire"
	dpb "github.com/idyl-labs/hyperplane-go/wire/deliveryv2"
)

// OpenClientServiceLane requests one STREAM lane from this client to an
// eligible connection of the Service named by exactPrincipal, its exact
// canonical SPIFFE ID in the client's Zone. The dock must have been opened
// with dock/3 (Config.Admission set) and its edge must have negotiated
// wire.ClientServiceLaneProfile; otherwise the request is refused locally
// with NAK_CODE_ADAPTER_MISMATCH and nothing is sent. The edge requires a
// lane policy that permits clients to reach that Service and checks it
// before revealing whether the Service is connected. The lane stays on the
// Service connection the edge selected for its whole life. Only the client
// opens a stream on the lane, and one stream only: the lane ends when that
// stream ends, from either end, and the client asks for a lane again. A
// second stream while one is open is refused with wire.DockCodeOverloaded.
// The Service answers on the client's stream. metadata is opaque
// application data, never identity or authority: at most 1,024 bytes; a
// larger request is refused.
//
// An edge refusal is a NakError. The returned lane has received its
// LaneAttached and is claimed from AcceptLane; its peer principal is
// advisory, so the application must authenticate the Service end to end.
// Canceling ctx before return interrupts setup; after success ctx does not
// close the established lane. The request stream is finished on every path.
func (d *Dock) OpenClientServiceLane(ctx context.Context, exactPrincipal string, metadata []byte) (_ *Lane, err error) {
	if d.control == nil {
		return nil, errors.New("dock: client service lanes need an admitted dock (use Open)")
	}
	if !d.node {
		return nil, errors.New("dock: client service lanes need a dock/3 client (set Config.Admission)")
	}
	if d.serviceLaneProfile != wire.ClientServiceLaneProfile {
		return nil, NakError{Code: dpb.NakCode_NAK_CODE_ADAPTER_MISMATCH}
	}
	principal, parseErr := spiffeid.FromString(exactPrincipal)
	if parseErr != nil || principal.String() != exactPrincipal {
		return nil, errors.New("dock: service target must be an exact canonical SPIFFE ID")
	}
	d.ensurePump()
	s, watch, err := d.openDelivery(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		FinishStream(s)
		releaseDelivery(ctx, watch, &err)
	}()
	if err := wire.WriteFrame(s, &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_OpenClientServiceLane{
		OpenClientServiceLane: &dpb.OpenClientServiceLane{ServicePrincipal: exactPrincipal, Metadata: metadata},
	}}); err != nil {
		return nil, err
	}
	var reply dpb.EdgeToRequester
	if err := wire.ReadFrame(s, &reply, 0); err != nil {
		return nil, err
	}
	switch m := reply.GetMsg().(type) {
	case *dpb.EdgeToRequester_Nak:
		return nil, NakError{Code: m.Nak.GetCode()}
	case *dpb.EdgeToRequester_LaneOpened:
		confirms := m.LaneOpened.GetTargetConfirms()
		if m.LaneOpened.GetLaneId() == 0 || len(confirms) != 1 ||
			confirms[0].GetPrincipal() != exactPrincipal || confirms[0].GetGen() != nil {
			return nil, errors.New("dock: malformed client service lane confirmation")
		}
		lane, err := d.WaitLane(ctx, m.LaneOpened.GetLaneId())
		if err != nil {
			return nil, err
		}
		if lane.PeerPrincipal() != exactPrincipal || lane.Classes() != wire.LaneClassStream {
			return nil, errors.New("dock: client service lane attachment differs from confirmation")
		}
		return lane, nil
	default:
		return nil, errors.New("dock: unexpected reply to OpenClientServiceLane")
	}
}
