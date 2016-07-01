//
// Interfaces for visiting interesting elements within and Android DEX
// file. These focus narrowly on methods; there are many of the
// aspects of APK and DEX files that could be visited but are
// not. Visit order is logically top-down, e.g.
//
//        VisitAPK("mumble.apk")
//          VisitDEX("classes1.dex")
//            VisitClass("foo", 1)
//              VisitMethod("foomethod1", 0, 400)
//            VisitClass("bar", 2)
//              VisitMethod("barmethod1", 1, 500)
//          VisitDEX("classes2.dex")
//           ...
//
package dexapkvisit

type DexVisitor interface {
	VisitDEX(dexname string, sha1signature [20]byte)
	VisitClass(classname string, nmethods uint32)
	VisitMethod(methodname string, methodIdx uint64, codeOffset uint64)
}
type ApkVisitor interface {
	VisitAPK(apk string)
}
type DexApkVisitor interface {
	DexVisitor
	ApkVisitor
	Verbose(vlevel int, s string, a ...interface{})
}
