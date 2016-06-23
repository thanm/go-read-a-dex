package dexread

import (
	"testing"
)

func TestDecodeDescriptor(t *testing.T) {

	type DecodeTest struct {
		Raw     string
		Decoded string
	}
	var raw = []string{
		"Lfrob/blar/blix;",
		"[Ljava/lang/Object;",
		"[[B",
		"[C",
		"D",
		"<illegal>",
	}
	var cooked = []string{
		"frob.blar.blix",
		"java.lang.Object[]",
		"byte[][]",
		"char[]",
		"double",
		"<illegal>",
	}
	for pos, r := range raw {
		c := decodeDescriptor(r)
		if c != cooked[pos] {
			t.Errorf("DecodeTest: raw=%s decoded='%s' wanted '%s'",
				r, c, cooked[pos])
		}
	}
}
