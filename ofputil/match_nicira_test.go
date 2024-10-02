package ofputil

import (
	"github.com/sensify-security/openflow/internal/encodingtest"
	"testing"
)

func TestMatchNxConjID(t *testing.T) {
	m := MatchNxConjID(42)
	tests := []encodingtest.MU{{ReadWriter: &m, Bytes: []byte{
		0x00, 0x01, // OpenFlow nicira 1.
		0x4a,                   // Match type: NXMTypeConjID << 1
		0x04,                   // Payload length.
		0x00, 0x00, 0x00, 0x2a, // Payload.
	}}}

	encodingtest.RunMU(t, tests)
}
