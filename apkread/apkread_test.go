package apkread

import (
	"fmt"
	"strings"
	"testing"
)

type captureDexApkVisitOperations struct {
	result []string
}

func (c *captureDexApkVisitOperations) VisitAPK(apk string) {
	c.result = append(c.result, fmt.Sprintf("APK %s\n", apk))
}

func (c *captureDexApkVisitOperations) VisitDEX(dexname string, sha1signature [20]byte) {
	c.result = append(c.result, fmt.Sprintf(" DEX %s sha1 %x\n", dexname, sha1signature))
}

func (c *captureDexApkVisitOperations) VisitClass(classname string, nmethods uint32) {
	c.result = append(c.result, fmt.Sprintf("  class %s methods: %d\n",
		classname, nmethods))
}

func (c *captureDexApkVisitOperations) VisitMethod(methodname string, methodIdx uint64, codeOffset uint64) {
	c.result = append(c.result, fmt.Sprintf("   method id %d name '%s' code offset %d\n", methodIdx, methodname, codeOffset))
}

func (c *captureDexApkVisitOperations) Verbose(vlevel int, s string, a ...interface{}) {
}

func TestSmallApkRead(t *testing.T) {

	visitor := &captureDexApkVisitOperations{}
	ReadAPK("testdata/fibonacci.apk", visitor)

	expected := "foo"
	actual := strings.Join(visitor.result, "\n")

	if actual != expected {
		t.Errorf("TestSmallApkRead: got '%s' expected '%s'",
			visitor.result, expected)
	}
}
