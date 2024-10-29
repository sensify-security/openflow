// Copyright 2024 Xage Security, Inc. All rights reserved.

package ofp

import "fmt"

// XMType defines the flow match field types for OpenFlow basic class.
type NXMType XMType

var nxmTypeText = map[NXMType]string{
	NXMTypeConjID:  "NXMTypeConjID",
	NXMTypePktMark: "NXMTypePktMark",
	NXMTypeCtState: "NXMTypeCtState",
}

func (t NXMType) String() string {
	text, ok := nxmTypeText[t]
	if !ok {
		return fmt.Sprintf("NXMType(%d)", t)
	}
	return text
}

const (
	// NXMTypeConjID matches conjunction ID.
	NXMTypeConjID NXMType = 37

	// NXMTypePktMark matches skb mark.
	NXMTypePktMark NXMType = 33

	// NXMTypeCtState matches connection tracking state.
	NXMTypeCtState NXMType = 105

	// NXMTypeCtZone matches connection tracking zone.
	NXMTypeCtZone NXMType = 106

	// NXMTypeCtMark matches connection tracking mark.
	NXMTypeCtMark NXMType = 107

	// NXMTypeCtLabel matches connection tracking label.
	NXMTypeCtLabel NXMType = 108
)

const (
	CtStateNew    = 1 << 0
	CtStateEst    = 1 << 1
	CtStateRel    = 1 << 2
	CtStateRpl    = 1 << 3
	CtStateInv    = 1 << 4
	CtStateTrk    = 1 << 5
	CtStateSrcNAT = 1 << 6
	CtStateDstNAT = 1 << 7
	CtStateNAT    = 1 << 8
	CtStateRelInv = 1 << 9
	CtStateRelRpl = 1 << 10
	CtStateEstInv = 1 << 11
	CtStateEstRpl = 1 << 12
	CtStateTrkInv = 1 << 13
	CtStateTrkRpl = 1 << 14
	CtStateLabel  = 1 << 15
	CtStateUnsupp = 1 << 16
)
