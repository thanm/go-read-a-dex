//
// This package contains helper functions that are common to the
// unit tests for the dexread and apkread packages: a visitor class
// for capturing callbacks, and a whitespace squeeze helper routine.
//
package dexapktest

import (
	"fmt"
	"regexp"
)

// A visitor to pass to ReadDEX/ReadAPK during unit testing. It
// captures any callbacks into a slice of strings, which can then be
// examined/verified.
//
type CaptureDexApkVisitOperations struct {
	Result []string
}

func (c *CaptureDexApkVisitOperations) VisitAPK(apk string) {
	c.Result = append(c.Result, fmt.Sprintf("APK %s", apk))
}

func (c *CaptureDexApkVisitOperations) VisitDEX(dexname string, sha1signature [20]byte) {
	c.Result = append(c.Result, fmt.Sprintf(" DEX %s sha1 %x", dexname, sha1signature))
}

func (c *CaptureDexApkVisitOperations) VisitClass(classname string, nmethods uint32) {
	c.Result = append(c.Result, fmt.Sprintf("  class %s methods: %d",
		classname, nmethods))
}

func (c *CaptureDexApkVisitOperations) VisitMethod(methodname string, methodIdx uint64, codeOffset uint64) {
	c.Result = append(c.Result, fmt.Sprintf("   method id %d name '%s' code offset %d", methodIdx, methodname, codeOffset))
}

func (c *CaptureDexApkVisitOperations) Verbose(vlevel int, s string, a ...interface{}) {
}

// Squeeze repeated whitespace and convert tabs/newlines to spaces.
func SqueezeWhite(s string) string {
	re := regexp.MustCompile(`[ \n\t]+`)
	return re.ReplaceAllLiteralString(s, " ")
}
