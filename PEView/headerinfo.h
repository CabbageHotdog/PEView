#pragma once

// 대충 53개
#define LINE "---------------------------------------------------------------"
#define IMAGE_DOS_HEADER_COUNT 19
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8

// 옵션 값
#define DISPLAY_ALL 0
#define DISPLAY_DOS_HEADER 1
#define DISPLAY_DOS_STUB 2
#define DISPLAY_NT_HEADER 3
#define DISPLAY_FILE_HEADER 4
#define DISPLAY_OPTIONAL_HEADER 5
#define DISPLAY_SECTION_HEADER 6
#define DISPLAY_IMPORT_DIRECTORY_TABLE 7
#define DISPLAY_IMPORT_NAME_TABLE 8

#define ADDRESS_MOD_FILE_OFFSET 0
#define ADDRESS_MOD_VITUAL_ADDRESS 1
#define ADDRESS_MOD_RELATIVE_VITUAL_ADDRESS 2

#define VIEW_MOD_RAW_DATA 0
#define VIEW_MOD_VALUE 1
#define VIEW_MOD_MAINPOINT 2
#define VIEW_MOD_HELP 3

// Image_File_Header Characteristics 특성 값
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
#define IMAGE_FILE_AFFRESIVE_WS_TRIM 0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080
#define IMAGE_FILE_32BIT_MACHINE 0x0100
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200
#define IMAGE_FILE_REMOVEABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUM_FROM_SWAP 0x0800
#define IMAGE_FILE_SYSTEM 0x1000
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000

// Image_File_Header Machine 종류 값
#define IMAGE_FILE_MACHINE_UNKNOWN 0x0
#define IMAGE_FILE_MACHINE_AM33 0x1d3
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_ARM 0x1c0
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define IMAGE_FILE_MACHINE_ARMNT 0x1c4
#define IMAGE_FILE_MACHINE_EBC 0xebc
#define IMAGE_FILE_MACHINE_I386 0x14c
#define IMAGE_FILE_MACHINE_IA64 0x200
#define IMAGE_FILE_MACHINE_LOONGARCH32 0x6232
#define IMAGE_FILE_MACHINE_LOONGARCH64 0x6264
#define IMAGE_FILE_MACHINE_M32R 0x9041
#define IMAGE_FILE_MACHINE_MIPS16 0x266
#define IMAGE_FILE_MACHINE_MIPSFPU 0x366
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x466
#define IMAGE_FILE_MACHINE_POWERRPC 0x1f0
#define IMAGE_FILE_MACHINE_POWERPCFP 0x1f1
#define IMAGE_FILE_MACHINE_R4000 0x166
#define IMAGE_FILE_MACHINE_RISCV32 0x5032
#define IMAGE_FILE_MACHINE_RISCV64 0x5064
#define IMAGE_FILE_MACHINE_RISCV128 0x5128
#define IMAGE_FILE_MACHINE_SH3 0xa02
#define IMAGE_FILE_MACHINE_SH3DSP 0x1a3
#define IMAGE_FILE_MACHINE_SH4 0x1a6
#define IMAGE_FILE_MACHINE_SH5 0x1a8
#define IMAGE_FILE_MACHINE_THUMB 0x1c2
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x169
 
// Image_Optional_Header DllCharacteristics 특성 값
#define IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA 0x0020
#define IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 0x0040
#define IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY 0x0080
#define IMAGE_DLLCHARACTERISTICS_NX_COMPAT 0x0100
#define IMAGE_DLLCHARACTERISTICS_NO_ISOLATION 0x0200
#define IMAGE_DLLCHARACTERISTICS_NO_SEH 0x0400
#define IMAGE_DLLCHARACTERISTICS_NO_BIND 0x0800
#define IMAGE_DLL_CHARACTERISTICS_APPCONTAINER 0x1000
#define IMAGE_DLLCHARACTERISTICS_WDM_DRIVER 0x2000
#define IMAGE_DLL_CHARACTERISTICS_GUARD_CF 0x4000
#define IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE 0x8000

// Image_Section_Header Characteristics 특성 값
#define IMAGE_SCN_TYPE_NO_PAD 0x00000008
#define IMAGE_SCN_CNT_CODE 0x00000020
#define IMAGE_SCN_CNT_INITIALIZED_DATA 0x00000040
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA 0x00000080
#define IMAGE_SCN_LNK_OTHER 0x00000100
#define IMAGE_SCN_LNK_INFO 0x00000200
#define IMAGE_SCN_LNK_REMOVE 0x00000800
#define IMAGE_SCN_LNK_COMDAT 0x00001000
#define IMAGE_SCN_GPREL 0x00008000
#define IMAGE_SCN_ALIGN_1BYTES 0x00100000
#define IMAGE_SCN_ALIGN_2BYTES 0x00200000
#define IMAGE_SCN_ALIGN_4BYTES 0x00300000
#define IMAGE_SCN_ALIGN_8BYTES 0x00400000
#define IMAGE_SCN_ALIGN_16BYTES 0x00500000
#define IMAGE_SCN_ALIGN_32BYTES 0x00600000
#define IMAGE_SCN_ALIGN_64BYTES 0x00700000
#define IMAGE_SCN_ALIGN_128BYTES 0x00800000
#define IMAGE_SCN_ALIGN_256BYTES 0x00900000
#define IMAGE_SCN_ALIGN_512BYTES 0x00a00000
#define IMAGE_SCN_ALIGN_1024BYTES 0x00b00000
#define IMAGE_SCN_ALIGN_2048BYTES 0x00c00000
#define IMAGE_SCN_ALIGN_4096BYTES 0x00d00000
#define IMAGE_SCN_ALIGN_8192BYTES 0x00e00000
#define IMAGE_SCN_LNK_NRELOC_OVFL 0x01000000
#define IMAGE_SCN_MEM_DISCARDALBE 0x02000000
#define IMAGE_SCN_MEM_NOT_CACHED 0x04000000
#define IMAGE_SCN_MEM_NOT_PAGED 0x08000000
#define IMAGE_SCN_MEM_SHARED 0x10000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ 0x40000000
#define IMAGE_SCN_MEM_WRITE 0x80000000


typedef unsigned char BYTE, * PBYTE, * LPBYTE;
typedef unsigned short WORD, * PWORD, * LPWORD;
typedef long LONG, * PLONG, * LPLONG;
typedef unsigned long DWORD, * PDWORD, * LPDWORD;
typedef unsigned __int64 ULONGLONG;

typedef struct _OPTION {
	char Address_mod;
	char View_mod;
	char display;
} OPTION;

typedef struct _HEADER_INFO {
	int ImageDosHeaderAddress;
	int ImageDosHeaderSize;
	int MSDosStubProgramAddress;
	int MSDosStubProgramSize;
	int ImageNTHeadersAddress;
	int ImageNtHeadersSize;
	int ImageFileHeaderAddress;
	int ImageFileHeaderSize;
	int ImageOptionalHeaderAddress;
	int ImageOptionalHeaderSize;
	int ImageSectionHeaderAddress[10];
	int ImageSectionHeaderSize;
} HEADER_INFO;

typedef struct _IMAGE_DOS_HEADER {
	WORD e_magic;
	WORD e_cblp;
	WORD e_cp;
	WORD e_crlc;
	WORD e_cparhdr;
	WORD e_minalloc;
	WORD e_maxalloc;
	WORD e_ss;
	WORD e_sp;
	WORD e_csum;
	WORD e_ip;
	WORD e_cs;
	WORD e_lfarlc;
	WORD e_ovno;
	WORD e_res[4];
	WORD e_oemid;
	WORD e_oeminfo;
	WORD e_res2[10];
	LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
	WORD  Machine;
	WORD  NumberOfSections;
	DWORD TimeDateStamp;
	DWORD PointerToSymbolTable;
	DWORD NumberOfSymbols;
	WORD  SizeOfOptionalHeader;
	WORD  Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
	DWORD VirtualAddress;
	DWORD Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
	WORD                 Magic;
	BYTE                 MajorLinkerVersion;
	BYTE                 MinorLinkerVersion;
	DWORD                SizeOfCode;
	DWORD                SizeOfInitializedData;
	DWORD                SizeOfUninitializedData;
	DWORD                AddressOfEntryPoint;
	DWORD                BaseOfCode;
	DWORD                BaseOfData;
	DWORD                ImageBase;
	DWORD                SectionAlignment;
	DWORD                FileAlignment;
	WORD                 MajorOperatingSystemVersion;
	WORD                 MinorOperatingSystemVersion;
	WORD                 MajorImageVersion;
	WORD                 MinorImageVersion;
	WORD                 MajorSubsystemVersion;
	WORD                 MinorSubsystemVersion;
	DWORD                Win32VersionValue;
	DWORD                SizeOfImage;
	DWORD                SizeOfHeaders;
	DWORD                CheckSum;
	WORD                 Subsystem;
	WORD                 DllCharacteristics;
	DWORD                SizeOfStackReserve;
	DWORD                SizeOfStackCommit;
	DWORD                SizeOfHeapReserve;
	DWORD                SizeOfHeapCommit;
	DWORD                LoaderFlags;
	DWORD                NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
	WORD        Magic;
	BYTE        MajorLinkerVersion;
	BYTE        MinorLinkerVersion;
	DWORD       SizeOfCode;
	DWORD       SizeOfInitializedData;
	DWORD       SizeOfUninitializedData;
	DWORD       AddressOfEntryPoint;
	DWORD       BaseOfCode;
	ULONGLONG   ImageBase;
	DWORD       SectionAlignment;
	DWORD       FileAlignment;
	WORD        MajorOperatingSystemVersion;
	WORD        MinorOperatingSystemVersion;
	WORD        MajorImageVersion;
	WORD        MinorImageVersion;
	WORD        MajorSubsystemVersion;
	WORD        MinorSubsystemVersion;
	DWORD       Win32VersionValue;
	DWORD       SizeOfImage;
	DWORD       SizeOfHeaders;
	DWORD       CheckSum;
	WORD        Subsystem;
	WORD        DllCharacteristics;
	ULONGLONG   SizeOfStackReserve;
	ULONGLONG   SizeOfStackCommit;
	ULONGLONG   SizeOfHeapReserve;
	ULONGLONG   SizeOfHeapCommit;
	DWORD       LoaderFlags;
	DWORD       NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS32 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_NT_HEADERS64 {
	DWORD Signature;
	IMAGE_FILE_HEADER FileHeader;
	IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union {
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	} Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
	WORD NumberOfRelocations;
	WORD NumberOfLinenumbers;
	DWORD Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD Characteristics;
		DWORD OriginalFirstThunk;
	};
	DWORD TimeDataStamp;
	DWORD ForwarderChain;
	DWORD Name;
	DWORD FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
	WORD Hint;
	BYTE *Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

void CheckCharacteristicsFileHeader(WORD ch);
void CheckMachineFileHeader(WORD m);
void CheckDllCharacteristicsOptionalHeader(WORD ch);
void CheckCharacteristiceSectionHeaders(DWORD ch);