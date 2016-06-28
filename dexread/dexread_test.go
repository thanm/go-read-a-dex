package dexread

import (
	"fmt"
	"strings"
	"testing"

	"github.com/thanm/go-read-a-dex/dexapktest"
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

func TestSmallDexFileRead(t *testing.T) {
	visitor := &dexapktest.CaptureDexApkVisitOperations{}
	ReadDEXFile("testdata/classes.dex", visitor)
	actual := strings.Join(visitor.Result, "\n")

	expected := ` DEX testdata/classes.dex
            sha1 fd56aced78355c305a9503d6f3dfe1f7ff6ac440
		    class fibonacci methods: 6
		    method id 0 name '<init>' code offset 584
		    method id 1 name 'ifibonacci' code offset 608
		    method id 2 name 'main' code offset 656
		    method id 3 name 'rcnm1' code offset 1008
		    method id 4 name 'rcnm2' code offset 1040
		    method id 5 name 'rfibonacci' code offset 1072`

	fmt.Println(actual)
	fmt.Println(expected)
	fmt.Println(dexapktest.SqueezeWhite(actual))
	fmt.Println(dexapktest.SqueezeWhite(expected))

	if dexapktest.SqueezeWhite(actual) != dexapktest.SqueezeWhite(expected) {
		t.Errorf("TestSmallApkRead: got '%s' expected '%s'",
			actual, expected)
	}
}
