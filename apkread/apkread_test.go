package apkread

import (
	"fmt"
	"strings"
	"testing"

	"github.com/thanm/go-read-a-dex/dexapktest"
)

func TestSmallApkRead(t *testing.T) {

	visitor := &dexapktest.CaptureDexApkVisitOperations{}
	ReadAPK("testdata/fibonacci.apk", visitor)
	actual := strings.Join(visitor.Result, "\n")

	expected := `APK testdata/fibonacci.apk
		  DEX classes.dex sha1 fd56aced78355c305a9503d6f3dfe1f7ff6ac440
		   class fibonacci methods: 6
		    method id 0 name '<init>' code offset 584
		    method id 1 name 'ifibonacci' code offset 608
		    method id 2 name 'main' code offset 656
		    method id 3 name 'rcnm1' code offset 1008
		    method id 4 name 'rcnm2' code offset 1040
		    method id 5 name 'rfibonacci' code offset 1072`

	if dexapktest.SqueezeWhite(actual) != dexapktest.SqueezeWhite(expected) {
		t.Errorf("got '%s' expected '%s'",
			visitor.Result, expected)
	}
}

func TestNonexistentApkRead(t *testing.T) {
	visitor := &dexapktest.CaptureDexApkVisitOperations{}
	err := ReadAPK("X", visitor)
	if err == nil {
		t.Errorf("TestNonexistentApkRead: expected error")
		return
	}
	actual := fmt.Sprintf("%v", err)
	expected := "unable to open APK X: open X: no such file or directory"
	if actual != expected {
		t.Errorf("expected '%s' got '%s', f error", expected, actual)
	}
}

func TestBadApkFileRead(t *testing.T) {
	visitor := &dexapktest.CaptureDexApkVisitOperations{}
	err := ReadAPK("apkread.go", visitor)
	if err == nil {
		t.Errorf("expected error")
		return
	}
	actual := fmt.Sprintf("%v", err)
	expected := "unable to open APK apkread.go: zip: not a valid zip file"
	if actual != expected {
		t.Errorf("expected '%s' got '%s', f error", expected, actual)
	}
}
