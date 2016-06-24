package apkread

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

type captureDexApkVisitOperations struct {
	result []string
}

func (c *captureDexApkVisitOperations) VisitAPK(apk string) {
	c.result = append(c.result, fmt.Sprintf("APK %s", apk))
}

func (c *captureDexApkVisitOperations) VisitDEX(dexname string, sha1signature [20]byte) {
	c.result = append(c.result, fmt.Sprintf(" DEX %s sha1 %x", dexname, sha1signature))
}

func (c *captureDexApkVisitOperations) VisitClass(classname string, nmethods uint32) {
	c.result = append(c.result, fmt.Sprintf("  class %s methods: %d",
		classname, nmethods))
}

func (c *captureDexApkVisitOperations) VisitMethod(methodname string, methodIdx uint64, codeOffset uint64) {
	c.result = append(c.result, fmt.Sprintf("   method id %d name '%s' code offset %d", methodIdx, methodname, codeOffset))
}

func (c *captureDexApkVisitOperations) Verbose(vlevel int, s string, a ...interface{}) {
}

func squeezeWhite(s string) string {
	re := regexp.MustCompile(`[ \t]+`)
	return re.ReplaceAllLiteralString(s, " ")
}

func TestSmallApkRead(t *testing.T) {

	visitor := &captureDexApkVisitOperations{}
	ReadAPK("testdata/fibonacci.apk", visitor)

	expected := `APK testdata/fibonacci.apk
		  DEX classes.dex sha1 fd56aced78355c305a9503d6f3dfe1f7ff6ac440
		   class fibonacci methods: 6
		    method id 0 name '<init>' code offset 584
		    method id 1 name 'ifibonacci' code offset 608
		    method id 2 name 'main' code offset 656
		    method id 3 name 'rcnm1' code offset 1008
		    method id 4 name 'rcnm2' code offset 1040
		    method id 5 name 'rfibonacci' code offset 1072`

	fmt.Printf("expected is: %s\n", squeezeWhite(expected))

	actual := strings.Join(visitor.result, "\n")

	fmt.Printf("actual is: %s\n", actual)
	fmt.Printf("sq(actual) is: %s\n", squeezeWhite(actual))

	if squeezeWhite(actual) != squeezeWhite(expected) {
		t.Errorf("TestSmallApkRead: got '%s' expected '%s'",
			visitor.result, expected)
	}
}
