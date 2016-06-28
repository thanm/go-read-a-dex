package dexread

//
// Rudimentary package for examining DEX files. See:
//
//   https://source.android.com/devices/tech/dalvik/dex-format.html
//
// for a specification of the DEX file format.
//
// This package focuses on the classes and methods in a DEX file;
// you pass it a visitor object and it will invoke interfaces on
// the visitor for each DEX class and DEX method in the DEX file
// of interest.
//

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/thanm/go-read-a-dex/dexapkvisit"
)

type dexState struct {
	apk        *string
	dexName    string
	b          bytes.Buffer
	rdr        *bytes.Reader
	methodIds  []DexMethodIdItem
	typeIds    []uint32
	strings    []string
	fileHeader DexFileHeader
	visitor    dexapkvisit.DexApkVisitor
}

func issueError(state *dexState, fmtstring string, a ...interface{}) {
	gripe := fmt.Sprintf(fmtstring, a...)
	apkPre := ""
	if state.apk != nil {
		apkPre = fmt.Sprintf("apk %s ", state.apk)
	}
	msg := fmt.Sprintf("reading %sdex %s: %s", apkPre, state.dexName, gripe)
	log.Fatalf(msg)
}

// Examine the contents of the DEX file that that is pointed to by the eader 'reader'. In the case that the DEX file is embedded within an APK file, 'apk' wil;l point to the APK name (for error reporting purposes).
func ReadDEXFile(dexFilePath string, visitor dexapkvisit.DexApkVisitor) {
	fi, err := os.Stat(dexFilePath)
	if err != nil {
		log.Fatalf("unable to access dex file %s", dexFilePath)
	}
	dfile, err := os.Open(dexFilePath)
	if err != nil {
		log.Fatalf("unable to open dex file %s", dexFilePath)
	}
	defer dfile.Close()
	ReadDEX(nil, dexFilePath, dfile, uint64(fi.Size()), visitor)
}

// Examine the contents of the DEX file that that is pointed to by the eader 'reader'. In the case that the DEX file is embedded within an APK file, 'apk' wil;l point to the APK name (for error reporting purposes).
func ReadDEX(apk *string, dexName string, reader io.Reader, expectedSize uint64, visitor dexapkvisit.DexApkVisitor) {
	state := dexState{apk: apk, dexName: dexName, visitor: visitor}

	// NB: the following seems clunky/inelegant (reading in entire contents
	// of DEX and then creating a new bytes.Reader to muck around within it).
	// Is there a more elegant way to do this? Maybe io.SectionReader?

	// Read in the whole enchilada
	nread, err := io.Copy(&state.b, reader)
	if err != nil {
		issueError(&state, "%v", err)
	}
	if uint64(nread) != expectedSize {
		issueError(&state, "expected %d bytes read %d", expectedSize, nread)
	}
	state.rdr = bytes.NewReader(state.b.Bytes())

	// Unpack file header and verify magic string
	state.fileHeader = unpackDexFileHeader(&state)

	// Invoke visitor callback
	visitor.VisitDEX(dexName, state.fileHeader.Sha1Sig)

	// Read method ids
	state.methodIds = unpackMethodIds(&state)

	// Read type ids
	state.typeIds = unpackTypeIds(&state)

	// Read strings
	state.strings = unpackStringIds(&state)

	// Dive into each class
	numClasses := state.fileHeader.ClassDefsSize
	off := state.fileHeader.ClassDefsOff
	for cl := uint32(0); cl < numClasses; cl++ {
		classHeader := unpackDexClass(&state, off)
		visitor.Verbose(1, "class %d type idx is %d", cl, classHeader.ClassIdx)
		examineClass(&state, &classHeader)
		off += DexClassHeaderSize
	}
}

func unpackDexFileHeader(state *dexState) DexFileHeader {
	var retval DexFileHeader

	// NB: do I really need a loop here? it would be nice to
	// compare slices using a single operation -- wondering if
	// there is some more idiomatic way to do this
	headerBytes := state.b.Bytes()
	DexFileMagic := [8]byte{0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00}
	for i := 0; i < 8; i++ {
		if DexFileMagic[i] != headerBytes[i] {
			issueError(state, "not a DEX file")
		}
	}

	// Populate the header file struct
	err := binary.Read(state.rdr, binary.LittleEndian, &retval)
	if err != nil {
		issueError(state, "unable to decode DEX header")
	}

	return retval
}

// Can't use io.SeekStart with gccgo (libgo not up to date)
const ioSeekStart = 0

func seekReader(state *dexState, off uint32) {
	_, err := state.rdr.Seek(int64(off), ioSeekStart)
	if err != nil {
		issueError(state, "unable to seek to offset %d", off)
	}
}

func unpackDexClass(state *dexState, off uint32) DexClassHeader {
	var retval DexClassHeader

	seekReader(state, off)
	err := binary.Read(state.rdr, binary.LittleEndian, &retval)
	if err != nil {
		issueError(state, "unable to decode class header")
	}

	return retval
}

type ulebHelper struct {
	data []byte
}

func (a *ulebHelper) grabULEB128() uint64 {
	v, size := binary.Uvarint(a.data)
	a.data = a.data[size:]
	return v
}

//
// For the rules on how type descriptors are encoded, see
// https://source.android.com/devices/tech/dalvik/dex-format.html#typedescriptor
//
func decodeDescriptor(d string) string {
	// count array dimensions
	var dims int = 0
	pos := 0
	c := '0'
	for pos, c = range d {
		if c == '[' {
			dims++
		} else {
			break
		}
	}

	var base string
	if c == 'L' {
		// reference
		base = strings.Replace(d[pos+1:], "/", ".", -1)
		base = strings.Replace(base, ";", "", 1)
	} else {
		// primitive
		switch c {
		case 'B':
			base = "byte"
		case 'C':
			base = "char"
		case 'D':
			base = "double"
		case 'F':
			base = "float"
		case 'I':
			base = "int"
		case 'J':
			base = "long"
		case 'S':
			base = "short"
		case 'Z':
			base = "boolean"
		case 'V':
			base = "void"
		default:
			// something went wrong, punt...
			return d
		}
	}

	for i := 0; i < dims; i++ {
		base += "[]"
	}

	return base
}

func getClassName(state *dexState, ci *DexClassHeader) string {
	typeidx := state.typeIds[ci.ClassIdx]
	typename := state.strings[typeidx]
	return decodeDescriptor(typename)
}

func examineClass(state *dexState, ci *DexClassHeader) {

	// No class data? In theory this can happen
	if ci.ClassDataOff == 0 {
		state.visitor.VisitClass(getClassName(state, ci), 0)
		return
	}

	// Create new slice pointing to correct spot in buffer for class data
	content := state.b.Bytes()
	cldata := content[ci.ClassDataOff:]
	helper := ulebHelper{cldata}

	// Read four ULEB128 encoded values into struct
	var clh DexClassContents
	clh.numStaticFields = uint32(helper.grabULEB128())
	clh.numInstanceFields = uint32(helper.grabULEB128())
	clh.numDirectMethods = uint32(helper.grabULEB128())
	clh.numVirtualMethods = uint32(helper.grabULEB128())
	numMethods := clh.numDirectMethods + clh.numVirtualMethods

	// invoke visitor callback
	state.visitor.VisitClass(getClassName(state, ci), numMethods)

	state.visitor.Verbose(1, "num static fields is %d", clh.numStaticFields)
	state.visitor.Verbose(1, "num instance fields is %d", clh.numInstanceFields)
	state.visitor.Verbose(1, "num direct methods is %d", clh.numDirectMethods)
	state.visitor.Verbose(1, "num virtual methods is %d", clh.numVirtualMethods)

	// Not interested in field info, but we have to get by
	// that information to get to the interesting stuff
	// that follows (since it's ULEB, we can't skip over it
	// directly)
	numFields := clh.numStaticFields + clh.numInstanceFields
	for i := uint32(0); i < numFields; i++ {
		helper.grabULEB128() // field_idx
		helper.grabULEB128() // access_flags
	}

	//
	// Examine the methods. Note that method ID value read is a
	// difference from the index of the previous element in the list.
	//
	var methodIdx uint64 = 0
	for i := uint32(0); i < numMethods; i++ {
		methodDelta := helper.grabULEB128()
		if i == 0 || i == clh.numDirectMethods {
			methodIdx = methodDelta
		} else {
			methodIdx = methodIdx + methodDelta
		}
		_ = helper.grabULEB128() // access flags currently unused
		methodCodeOffset := helper.grabULEB128()
		state.visitor.Verbose(1, "method %d idx %d off %d",
			i, methodIdx, methodCodeOffset)

		examineMethod(state, methodIdx, methodCodeOffset)
	}
}

func unpackStringIds(state *dexState) []string {
	nStringIds := int(state.fileHeader.StringIdsSize)
	stringOffsets := make([]uint32, nStringIds, nStringIds)

	// position the reader at the right spot
	seekReader(state, state.fileHeader.StringIdsOff)

	// read offsets
	for i := 0; i < nStringIds; i++ {
		err := binary.Read(state.rdr, binary.LittleEndian, &stringOffsets[i])
		if err != nil {
			issueError(state, "string ID %d unpack failed", i)
		}
	}

	// now read in string data
	ret := make([]string, nStringIds, nStringIds)
	for i := 0; i < nStringIds; i++ {
		ret[i] = unpackModUTFString(state, stringOffsets[i])
	}
	return ret
}

func zLen(sd []byte) int {
	for i := 0; i < len(sd); i++ {
		if sd[i] == 0 {
			return i
		}
	}
	return len(sd)
}

//
// DEX file strings use a somewhat peculiar "Modified" UTF-8 encoding, details
// in https://source.android.com/devices/tech/dalvik/dex-format.html#mutf-8
//
func unpackModUTFString(state *dexState, off uint32) string {
	content := state.b.Bytes()
	sdata := content[off:]
	helper := ulebHelper{sdata}

	// unpack len and then string
	sl := helper.grabULEB128()
	return string(helper.data[:sl])
}

func unpackMethodIds(state *dexState) []DexMethodIdItem {
	nMethods := int(state.fileHeader.MethodIdsSize)
	ret := make([]DexMethodIdItem, nMethods, nMethods)

	// position the reader at the right spot
	seekReader(state, state.fileHeader.MethodIdsOff)

	// read in the array of method id items
	for i := 0; i < nMethods; i++ {
		err := binary.Read(state.rdr, binary.LittleEndian, &ret[i])
		if err != nil {
			issueError(state, "method ID %d unpack failed", i)
		}
	}

	state.visitor.Verbose(1, "read %d methodids", nMethods)

	return ret
}

// NB: this function has a lot in common with the one above it--
// what would be a good way to common them up? Generics would
// be useful here.

func unpackTypeIds(state *dexState) []uint32 {
	nTypeIds := int(state.fileHeader.TypeIdsSize)
	ret := make([]uint32, nTypeIds, nTypeIds)

	// position the reader at the right spot
	seekReader(state, state.fileHeader.TypeIdsOff)

	// read in the array of type id items
	for i := 0; i < nTypeIds; i++ {
		err := binary.Read(state.rdr, binary.LittleEndian, &ret[i])
		if err != nil {
			issueError(state, "type ID %d unpack failed", i)
		}
	}

	state.visitor.Verbose(1, "read %d typeids", nTypeIds)

	return ret
}

func examineMethod(state *dexState, methodIdx, methodCodeOffset uint64) {

	// Look up method name from method ID
	nameIdx := state.methodIds[methodIdx].NameIdx

	name := state.strings[nameIdx]

	state.visitor.VisitMethod(name, methodIdx, methodCodeOffset)
}
