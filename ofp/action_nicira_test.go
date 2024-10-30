// Copyright 2024 Xage Security, Inc. All rights reserved.

package ofp

import (
	"github.com/sensify-security/openflow/internal/encodingtest"
	"testing"
)

func TestActionNxConjunction(t *testing.T) {
	actConj := ActionNxConjunction{
		Clause:     1,
		NumClauses: 2,
		ID:         42,
	}
	tests := []encodingtest.MU{
		{ReadWriter: &actConj, Bytes: []byte{
			0xff, 0xff, // Action type - Experimenter.
			0x00, 0x10, // Action length.
			0x00, 0x00, 0x23, 0x20, // Vendor Nicira.
			0x00, 0x22, // Action type - Conjunction.
			0x01, 0x02, // Clause, NumClauses.
			0x00, 0x00, 0x00, 0x2a, // Id.
		}},
	}

	encodingtest.RunMU(t, tests)
}

func TestActionNxConntrack(t *testing.T) {
	actCtCommit := ActionNxConntrack{
		Flags:     uint16(NxCtFlagCommit),
		ZoneSrc:   0,
		ZoneRange: 0,
		RecircID:  0,
		Alg:       0,
	}

	actCtForce := ActionNxConntrack{
		Flags:     uint16(NxCtFlagForce),
		ZoneSrc:   0,
		ZoneRange: 0,
		RecircID:  0,
		Alg:       0,
	}
	tests := []encodingtest.MU{
		{ReadWriter: &actCtCommit, Bytes: []byte{
			0xff, 0xff, // Action type - Experimenter.
			0x00, 0x18, // Action length.
			0x00, 0x00, 0x23, 0x20, // Vendor Nicira.
			0x00, 0x23, // Action type - Conntrack.
			0x00, 0x01, // Flags.
			0x00, 0x00, 0x00, 0x00, // ZoneSrc.
			0x00, 0x00, // ZoneRange.
			0x00,             // RecircID.
			0x00, 0x00, 0x00, // Padding.
			0x00, 0x00, // Alg.
		}},
		{ReadWriter: &actCtForce, Bytes: []byte{
			0xff, 0xff, // Action type - Experimenter.
			0x00, 0x18, // Action length.
			0x00, 0x00, 0x23, 0x20, // Vendor Nicira.
			0x00, 0x23, // Action type - Conntrack.
			0x00, 0x02, // Flags.
			0x00, 0x00, 0x00, 0x00, // ZoneSrc.
			0x00, 0x00, // ZoneRange.
			0x00,             // RecircID.
			0x00, 0x00, 0x00, // Padding.
			0x00, 0x00, // Alg.
		}},
	}

	encodingtest.RunMU(t, tests)
}
