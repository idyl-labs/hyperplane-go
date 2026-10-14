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

// OpenServiceLane requests one STREAM lane from this admitted dock/3 Node to
// an eligible connection of exactPrincipal. The edge requires an explicit
// Node-only service grant even when scopes match, judges authority before
// target presence, and pins the selected generation for the lane's life.
// Only the Node initiates streams on this lane; the Service accepts them and
// responds on the same bidirectional stream without reverse-open authority.
// metadata is opaque application data, never identity or authority.
//
// The negotiated profile must be wire.NodeServiceLaneProfile. A missing or
// unknown profile is refused locally with NAK_CODE_ADAPTER_MISMATCH and no
// alternate request. An edge refusal is a NakError. The returned lane has
// received its LaneAttached and is claimed from AcceptLane; its peer principal
// is advisory, so the application must authenticate the peer end to end.
// Canceling ctx before return interrupts setup; after success ctx does not
// close the established lane. The one-shot request is finished on every path.
func (d *Dock) OpenServiceLane(ctx context.Context, exactPrincipal string, metadata []byte) (_ *Lane, err error) {
	if d.control == nil {
		return nil, errors.New("dock: service lanes need an admitted dock (use Open)")
	}
	if d.serviceLaneProfile != wire.NodeServiceLaneProfile {
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
	if err := wire.WriteFrame(s, &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_OpenServiceLane{
		OpenServiceLane: &dpb.OpenServiceLane{ServicePrincipal: exactPrincipal, Metadata: metadata},
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
			return nil, errors.New("dock: malformed service lane confirmation")
		}
		lane, err := d.WaitLane(ctx, m.LaneOpened.GetLaneId())
		if err != nil {
			return nil, err
		}
		if lane.PeerPrincipal() != exactPrincipal || lane.Classes() != wire.LaneClassStream {
			return nil, errors.New("dock: service lane attachment differs from confirmation")
		}
		return lane, nil
	default:
		return nil, errors.New("dock: unexpected reply to OpenServiceLane")
	}
}

// WithdrawServiceTarget removes this opted-in Service connection from new
// target selection. Ack means eligibility was removed before the reply; it
// does not mean established streams drained. Other connections of the same
// principal remain eligible, and existing lanes never move to a replacement.
// The Service retains this dock until its established lanes end, or closes it
// under its own drain and credential-lifetime policy. Repeating withdrawal on
// the same connection is idempotent. Missing profile or opt-in fails locally;
// edge refusal is a NakError. ctx bounds the finished one-shot exchange.
func (d *Dock) WithdrawServiceTarget(ctx context.Context) (err error) {
	if d.control == nil {
		return errors.New("dock: service withdrawal needs an admitted dock (use Open)")
	}
	if !d.serviceTarget || d.serviceLaneProfile != wire.NodeServiceLaneProfile {
		return NakError{Code: dpb.NakCode_NAK_CODE_ADAPTER_MISMATCH}
	}
	s, watch, err := d.openDelivery(ctx)
	if err != nil {
		return err
	}
	defer func() {
		FinishStream(s)
		releaseDelivery(ctx, watch, &err)
	}()
	if err := wire.WriteFrame(s, &dpb.RequesterToEdge{Msg: &dpb.RequesterToEdge_WithdrawServiceTarget{
		WithdrawServiceTarget: &dpb.WithdrawServiceTarget{},
	}}); err != nil {
		return err
	}
	var reply dpb.EdgeToRequester
	if err := wire.ReadFrame(s, &reply, 0); err != nil {
		return err
	}
	switch m := reply.GetMsg().(type) {
	case *dpb.EdgeToRequester_Ack:
		return nil
	case *dpb.EdgeToRequester_Nak:
		return NakError{Code: m.Nak.GetCode()}
	default:
		return errors.New("dock: unexpected reply to WithdrawServiceTarget")
	}
}
