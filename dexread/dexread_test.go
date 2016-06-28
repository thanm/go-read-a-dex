package dexread

import (
	"fmt"
	"strings"
	"testing"

	// NB: having to call out the full path in the import seems
	// unfriendly. Is there a way that I can make my go code more
	// location-independent (for example, if I decide to rename
	// go-read-a-dex or move it to some other location)?

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
	err := ReadDEXFile("testdata/classes.dex", visitor)
	if err != nil {
		t.Errorf("TestSmallApkRead: readDexFile error %v", err)
		return
	}

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

	if dexapktest.SqueezeWhite(actual) != dexapktest.SqueezeWhite(expected) {
		t.Errorf("TestSmallApkRead: got '%s' expected '%s'",
			actual, expected)
	}
}

func TestNonexistentDexFileRead(t *testing.T) {
	visitor := &dexapktest.CaptureDexApkVisitOperations{}
	err := ReadDEXFile("quix", visitor)
	if err == nil {
		t.Errorf("TestSmallApkRead: expected error")
		return
	}
	actual := fmt.Sprintf("%v", err)
	expected := "reading dex quix: os.Stat failed(): stat quix: no such file or directory"
	if actual != expected {
		t.Errorf("TestSmallApkRead: expected '%s' got '%s', f error", expected, actual)
	}
}

func TestBadDexFileRead(t *testing.T) {
	visitor := &dexapktest.CaptureDexApkVisitOperations{}
	err := ReadDEXFile("dexread.go", visitor)
	if err == nil {
		t.Errorf("TestSmallApkRead: expected error")
		return
	}
	actual := fmt.Sprintf("%v", err)
	expected := "reading dex dexread.go: not a DEX file"
	if actual != expected {
		t.Errorf("TestSmallApkRead: expected '%s' got '%s', f error", expected, actual)
	}
}
