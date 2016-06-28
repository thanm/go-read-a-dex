package dexread

const (
	// https://source.android.com/devices/tech/dalvik/dex-format.html#endian-constant
	endianConstant     = 0x12345678
	reverseEndianConst = 0x78563412
	dexFileHeaderSize  = 112
	dexClassHeaderSize = 32
)

//
// Upper case fields are intentional (to allow filling in the contents
// of this struct via reflection).
//
type dexFileHeader struct {
	// https://source.android.com/devices/tech/dalvik/dex-format.html#header-item
	Magic         [8]byte
	Checksum      uint32
	Sha1Sig       [20]byte
	FileSize      uint32
	HeaderSize    uint32
	EndianTag     uint32
	LinkSize      uint32
	LinkOff       uint32
	MapOff        uint32
	StringIdsSize uint32
	StringIdsOff  uint32
	TypeIdsSize   uint32
	TypeIdsOff    uint32
	ProtoIdsSize  uint32
	ProtoIdsOff   uint32
	PieldIdsSize  uint32
	FieldIdsOff   uint32
	MethodIdsSize uint32
	MethodIdsOff  uint32
	ClassDefsSize uint32
	ClassDefsOff  uint32
	DataSize      uint32
	DataOff       uint32
}

type dexClassHeader struct {
	// https://source.android.com/devices/tech/dalvik/dex-format.html#class-def-item
	ClassIdx        uint32
	AccessFlags     uint32
	SuperClassIdx   uint32
	InterfacesOff   uint32
	SourceFileIdx   uint32
	AnnotationsOff  uint32
	ClassDataOff    uint32
	StaticValuesOff uint32
}

type dexMethodIdItem struct {
	ClassIdx uint16
	TypeIdx  uint16
	NameIdx  uint32
}

//
// Note that within the DEX file, these fields are ULEB128 encoded; the
// struct below is to hold the decoded values.
//
type dexClassContents struct {
	// https://source.android.com/devices/tech/dalvik/dex-format.html#class-data-item
	numStaticFields   uint32
	numInstanceFields uint32
	numDirectMethods  uint32
	numVirtualMethods uint32
}
