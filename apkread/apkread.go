//
// Rudimentary package for examining Android APK files. An APK file
// is basically a ZIP file that contains an Android manifest and a series
// of DEX files, strings, resources, bitmaps, and assorted other items.
// This specific reader looks only at the DEX files, not the other
// bits and pieces (of which there are many).
//
package apkread

import (
	"archive/zip"
	"errors"
	"fmt"
	"regexp"

	. "github.com/thanm/go-read-a-dex/dexapkvisit"
	"github.com/thanm/go-read-a-dex/dexread"
)

// ReadAPK opens the specified APK file 'apk' and walks the contents
// of any DEX files it contains, making callbacks at various
// points through a user-supplied visitor object 'visitor'. See
// DexApkVisitor for more info on which DEX/APK parts are visited.
func ReadAPK(apk string, visitor DexApkVisitor) error {
	rc, err := zip.OpenReader(apk)
	if err != nil {
		return errors.New(fmt.Sprintf("unable to open APK %s: %v", apk, err))
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
			reader, err := z.File[i].Open()
			if err != nil {
				return errors.New(fmt.Sprintf("opening apk %s dex %s: %v", apk, entryName, err))
			}
			dexread.ReadDEX(&apk, entryName, reader,
				z.File[i].UncompressedSize64, visitor)
			reader.Close()
		}
	}
	return nil
}
