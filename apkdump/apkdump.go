package apkdump

import (
	"fmt"
)

//
// This implementation of the DexApkVisitor interface dumps
// out information about the APK/DEX contents to stdout
//
type DexApkDumper struct {
	Vlevel int
}

func (d *DexApkDumper) VisitAPK(apk string) {
	fmt.Printf("APK %s\n", apk)
}

func (d *DexApkDumper) VisitDEX(dexname string, sha1signature [20]byte) {

	fmt.Printf(" DEX %s sha1 %x\n", dexname, sha1signature)
}

func (d *DexApkDumper) VisitClass(classname string, nmethods uint32) {
	fmt.Printf("  class %s methods: %d\n", classname, nmethods)
}

func (d *DexApkDumper) VisitMethod(methodname string, methodIdx uint64, codeOffset uint64) {
	fmt.Printf("   method id %d name '%s' code offset %d\n",
		methodIdx, methodname, codeOffset)
}

func (d *DexApkDumper) Verbose(vlevel int, s string, a ...interface{}) {
	if d.Vlevel >= vlevel {
		fmt.Printf("++ ")
		fmt.Printf(s, a...)
		fmt.Printf("\n")
	}
}
