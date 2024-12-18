// Copyright 2024 Xage Security, Inc. All rights reserved.

package ofputil

import (
	"github.com/sensify-security/openflow/ofp"
)

// nicira creates an Openflow Nicira extensible match of the given type.
func nicira(t ofp.NXMType, val ofp.XMValue, mask ofp.XMValue) ofp.XM {
	return ofp.XM{
		Class: ofp.XMClassNicira1,
		Type:  ofp.XMType(t),
		Value: val,
		Mask:  mask,
	}
}

// MatchNxConjID creates an Openflow Nicira extensible match of conjunction ID.
func MatchNxConjID(id uint32) ofp.XM {
	return nicira(ofp.NXMTypeConjID, bytesOf(id), nil)
}

func MatchNxCtState(state, mask uint32) ofp.XM {
	return nicira(ofp.NXMTypeCtState, bytesOf(state), bytesOf(mask))
}
