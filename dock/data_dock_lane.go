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

// OpenDataDockLane requests one STREAM lane from this client to the Node
// data dock named by targetPrincipal, its exact SPIFFE ID (see
// wire/datadock.Principal). The dock must have been opened with dock/3
// (Config.Admission set); any other dock is refused locally. The edge
// requires a lane policy that admits clients to data docks and checks it
// before revealing whether the data dock is connected. The lane stays on the
// data dock connection the edge selected for its whole life; when that
// connection drains or ends, open a new lane. Either end may open streams;
// a client opens one per connection to a Computer, of class
// wire.LaneStreamClassE2EMTLS, whose attribution header is a
// wire/datadock.Header. metadata is opaque application data, never identity
// or authority.
//
// An edge refusal is a NakError. The returned lane has received its
// LaneAttached and is claimed from AcceptLane; its peer principal is
// advisory, so the application must authenticate the endpoint behind the
// data dock end to end. Canceling ctx before return interrupts setup; after
// success ctx does not close the established lane. The request stream is
// finished on every path.
func (d *Dock) OpenDataDockLane(ctx context.Context, targetPrincipal string, metadata []byte) (_ *Lane, err error) {
	if d.control == nil {
		return nil, errors.New("dock: data dock lanes need an admitted dock (use Open)")
	}
	if !d.node {
		return nil, errors.New("dock: data dock lanes need a dock/3 client (set Config.Admission)")
	}
	principal, parseErr := spiffeid.FromString(targetPrincipal)
	if parseErr != nil || principal.String() != targetPrincipal {
		return nil, errors.New("dock: data dock target must be an exact canonical SPIFFE ID")
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
	if err := wire.WriteFrame(s, &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_OpenDataDockLane{
		OpenDataDockLane: &dpb.OpenDataDockLane{TargetPrincipal: targetPrincipal, Metadata: metadata},
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
			confirms[0].GetPrincipal() != targetPrincipal || confirms[0].GetGen() != nil {
			return nil, errors.New("dock: malformed data dock lane confirmation")
		}
		lane, err := d.WaitLane(ctx, m.LaneOpened.GetLaneId())
		if err != nil {
			return nil, err
		}
		if lane.PeerPrincipal() != targetPrincipal || lane.Classes() != wire.LaneClassStream {
			return nil, errors.New("dock: data dock lane attachment differs from confirmation")
		}
		return lane, nil
	default:
		return nil, errors.New("dock: unexpected reply to OpenDataDockLane")
	}
}
