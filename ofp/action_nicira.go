// Copyright 2024 Xage Security, Inc. All rights reserved.
package ofp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/sensify-security/openflow/internal/encoding"
	"io"
)

const VENDOR_NICIRA = 0x00002320

type ActionNxType uint16
type NxCtFlags uint16

const (
	NxCtFlagCommit NxCtFlags = 1 << 0
	NxCtFlagForce  NxCtFlags = 1 << 1
)

// String returns a string representation of the action type.
func (a ActionNxType) String() string {
	text, ok := actionNxText[a]
	// If action is not known just say it.
	if !ok {
		return fmt.Sprintf("Action(%d)", a)
	}

	return text
}

const (
	// ActionNxTypeConjunction sets a conjunction clause.
	ActionNxTypeConjunction ActionNxType = 0x0022

	// ActionNxTypeConntrack commits the flow to conntrack table.
	ActionNxTypeConntrack ActionNxType = 0x0023
)

var actionNxText = map[ActionNxType]string{
	ActionNxTypeConjunction: "ActionNxTypeConj",
	ActionNxTypeConntrack:   "ActionNxTypeConntrack",
}

// niciraHeader defines a header of each Nicira action, it will be used for
// marshalling and unmarshalling actions.
type niciraHeader struct {
	Type ActionType // Type Experimenter.

	// Length of action, including this header.
	Len uint16

	VendorID uint32 // Vendor ID - 0x00002320.
	Subtype  ActionNxType
}

func (a *niciraHeader) ReadFrom(r io.Reader) (int64, error) {
	return encoding.ReadFrom(r, &a.Type, &a.Len, &a.VendorID, &a.Subtype)
}

// based on struct nx_action_conjunction in ovs/lib/ofp-actions.c
type ActionNxConjunction struct {
	Clause     uint8
	NumClauses uint8
	ID         uint32
}

func (a ActionNxConjunction) Type() ActionType {
	return ActionTypeExperimenter
}

func (a ActionNxConjunction) ReadFrom(r io.Reader) (int64, error) {
	return encoding.ReadFrom(r, &niciraHeader{}, &a.Clause, &a.NumClauses, &a.ID)
}

func (a ActionNxConjunction) WriteTo(w io.Writer) (int64, error) {
	buf := &bytes.Buffer{}

	const vendorID = uint32(VENDOR_NICIRA) // nicira extensions
	err := binary.Write(buf, binary.BigEndian, vendorID)
	if err != nil {
		return 0, err
	}
	const experimenterActionType = ActionNxTypeConjunction // NXAST_RAW_CONJUNCTION
	err = binary.Write(buf, binary.BigEndian, experimenterActionType)
	if err != nil {
		return 0, err
	}

	err = binary.Write(buf, binary.BigEndian, a.Clause)
	if err != nil {
		return 0, err
	}
	err = binary.Write(buf, binary.BigEndian, a.NumClauses)
	if err != nil {
		return 0, err
	}
	err = binary.Write(buf, binary.BigEndian, a.ID)
	if err != nil {
		return 0, err
	}
	length := uint16(buf.Len())
	length += 2 // for the type field
	length += 2 // for the length field
	err = binary.Write(w, binary.BigEndian, a.Type())
	if err != nil {
		return 0, err
	}
	err = binary.Write(w, binary.BigEndian, length)
	if err != nil {
		return 0, err
	}

	_, err = io.Copy(w, buf)
	if err != nil {
		return 0, err
	}
	return int64(length), nil
}

// ActionNxConntrack - based on struct nx_action_conntrack in ovs/lib/ofp-actions.c
type ActionNxConntrack struct {
	Flags     uint16
	ZoneSrc   uint32
	ZoneRange uint16
	RecircID  uint8
	Alg       uint16
}

func (a ActionNxConntrack) ReadFrom(r io.Reader) (int64, error) {
	return encoding.ReadFrom(r, &niciraHeader{}, &a.Flags, &a.ZoneSrc,
		&a.ZoneRange, &a.RecircID, &defaultPad3, &a.Alg)
}

func (a ActionNxConntrack) WriteTo(w io.Writer) (int64, error) {
	buf := &bytes.Buffer{}

	const vendorId = uint32(VENDOR_NICIRA) // nicira extensions
	err := binary.Write(buf, binary.BigEndian, vendorId)
	if err != nil {
		return 0, err
	}
	const experimenterActionType = uint16(0x0023) // NXAST_CT_COMMIT
	err = binary.Write(buf, binary.BigEndian, experimenterActionType)
	if err != nil {
		return 0, err
	}
	err = binary.Write(buf, binary.BigEndian, a.Flags)
	if err != nil {
		return 0, err
	}
	err = binary.Write(buf, binary.BigEndian, a.ZoneSrc)
	if err != nil {
		return 0, err
	}
	err = binary.Write(buf, binary.BigEndian, a.ZoneRange)
	if err != nil {
		return 0, err
	}
	err = binary.Write(buf, binary.BigEndian, a.RecircID)
	if err != nil {
		return 0, err
	}
	// padding is positional, hence cannot be moved around
	err = binary.Write(buf, binary.BigEndian, pad3{})
	if err != nil {
		return 0, err
	}
	err = binary.Write(buf, binary.BigEndian, a.Alg)
	if err != nil {
		return 0, err
	}
	length := uint16(buf.Len())
	length += 2 // for the type field
	length += 2 // for the length field
	err = binary.Write(w, binary.BigEndian, a.Type())
	if err != nil {
		return 0, err
	}
	err = binary.Write(w, binary.BigEndian, length)
	if err != nil {
		return 0, err
	}
	_, err = io.Copy(w, buf)
	if err != nil {
		return 0, err
	}
	return int64(length), nil
}

func (a ActionNxConntrack) Type() ActionType {
	return ActionTypeExperimenter
}
