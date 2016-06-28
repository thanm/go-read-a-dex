package main

//
// Rudimentary program for examining Android APK files. An APK file
// is basically a ZIP file that contains an Android manifest and a series
// of DEX files, strings, resources, bitmaps, and assorted other items.
// This specific reader looks only at the DEX files, not the other
// bits and pieces.
//

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/thanm/go-read-a-dex/apkdump"
	"github.com/thanm/go-read-a-dex/apkread"
)

var verbflag = flag.Int("v", 0, "Verbose trace output level")
var dumpflag = flag.Bool("dump", false, "Dump DEX/APK info to stdout")

func verb(vlevel int, s string, a ...interface{}) {
	if *verbflag >= vlevel {
		fmt.Printf(s, a...)
		fmt.Printf("\n")
	}
}

func usage(msg string) {
	if len(msg) > 0 {
		fmt.Fprintf(os.Stderr, "error: %s\n", msg)
	}
	fmt.Fprintf(os.Stderr, "usage: apkread [flags] <APK file>\n")
	flag.PrintDefaults()
	os.Exit(2)
}

//
// apkreader main function. Nothing to see here.
//
func main() {
	log.SetFlags(0)
	log.SetPrefix("apkreader: ")
	flag.Parse()
	verb(1, "in main")
	if flag.NArg() != 1 {
		usage("please supply an input APK file")
	}
	if !*dumpflag {
		usage("select one of: -dump")
	}
	verb(1, "APK is %s", flag.Arg(0))

	if *dumpflag {
		apkread.ReadAPK(flag.Arg(0), &apkdump.DexApkDumper{Vlevel: *verbflag})
	}
	verb(1, "leaving main")
}
