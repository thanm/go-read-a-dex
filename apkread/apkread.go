package apkread

//
// Rudimentary package for examining Android APK files. An APK file
// is basically a ZIP file that contains an Android manifest and a series
// of DEX files, strings, resources, bitmaps, and assorted other items.
// This specific reader looks only at the DEX files, not the other
// bits and pieces (of which there are many).
//

import (
	"archive/zip"
	"log"
	"regexp"

	. "github.com/thanm/go-read-a-dex/dexapkvisit"
	"github.com/thanm/go-read-a-dex/dexread"
)

func ReadAPK(apk string, visitor DexApkVisitor) {
	rc, err := zip.OpenReader(apk)
	if err != nil {
		log.Fatalf("unable to open APK %s (err=%v)", apk, err)
	}
	defer rc.Close()
	z := &rc.Reader

	visitor.VisitAPK(apk)
	visitor.Verbose(1, "APK %s contains %d entries", apk, len(z.File))

	isDex := regexp.MustCompile(`^\S+\.dex$`)
	for i := 0; i < len(z.File); i++ {
		entryName := z.File[i].Name
		if isDex.MatchString(entryName) {
			visitor.Verbose(1, "dex file %s at entry %d", entryName, i)
			dexread.ReadDEX(apk, entryName, z.File[i], visitor)
		}
	}
}