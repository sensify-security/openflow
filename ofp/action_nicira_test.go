package ofp

import (
	"github.com/sensify-security/openflow/internal/encodingtest"
	"testing"
)

func TestActionNxConjunction(t *testing.T) {
	actConj := ActionNxConjunction{
		Clause:     1,
		NumClauses: 2,
		Id:         42,
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
		Flags:      uint16(NxCtFlagCommit),
		Zone_src:   0,
		Zone_range: 0,
		Recirc_id:  0,
		Padding:    [3]uint8{},
		Alg:        0,
	}

	actCtForce := ActionNxConntrack{
		Flags:      uint16(NxCtFlagForce),
		Zone_src:   0,
		Zone_range: 0,
		Recirc_id:  0,
		Padding:    [3]uint8{},
		Alg:        0,
	}
	tests := []encodingtest.MU{
		{ReadWriter: &actCtCommit, Bytes: []byte{
			0xff, 0xff, // Action type - Experimenter.
			0x00, 0x18, // Action length.
			0x00, 0x00, 0x23, 0x20, // Vendor Nicira.
			0x00, 0x23, // Action type - Conntrack.
			0x00, 0x01, // Flags.
			0x00, 0x00, 0x00, 0x00, // Zone_src.
			0x00, 0x00, // Zone_range.
			0x00,             // Recirc_id.
			0x00, 0x00, 0x00, // Padding.
			0x00, 0x00, // Alg.
		}},
		{ReadWriter: &actCtForce, Bytes: []byte{
			0xff, 0xff, // Action type - Experimenter.
			0x00, 0x18, // Action length.
			0x00, 0x00, 0x23, 0x20, // Vendor Nicira.
			0x00, 0x23, // Action type - Conntrack.
			0x00, 0x02, // Flags.
			0x00, 0x00, 0x00, 0x00, // Zone_src.
			0x00, 0x00, // Zone_range.
			0x00,             // Recirc_id.
			0x00, 0x00, 0x00, // Padding.
			0x00, 0x00, // Alg.
		}},
	}

	encodingtest.RunMU(t, tests)
}
