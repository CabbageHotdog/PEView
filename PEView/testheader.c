#include "headerinfo.h"

int FileHeaderCharacteristics[] = { IMAGE_FILE_RELOCS_STRIPPED ,IMAGE_FILE_EXECUTABLE_IMAGE ,IMAGE_FILE_LINE_NUMS_STRIPPED
,IMAGE_FILE_LOCAL_SYMS_STRIPPED ,IMAGE_FILE_AFFRESIVE_WS_TRIM,IMAGE_FILE_LARGE_ADDRESS_AWARE,IMAGE_FILE_BYTES_REVERSED_LO
,IMAGE_FILE_32BIT_MACHINE,IMAGE_FILE_DEBUG_STRIPPED,IMAGE_FILE_REMOVEABLE_RUN_FROM_SWAP,IMAGE_FILE_NET_RUM_FROM_SWAP
,IMAGE_FILE_SYSTEM ,IMAGE_FILE_DLL ,IMAGE_FILE_UP_SYSTEM_ONLY ,IMAGE_FILE_BYTES_REVERSED_HI };

int FileHeaderMachine[] = { IMAGE_FILE_MACHINE_UNKNOWN, IMAGE_FILE_MACHINE_AM33, IMAGE_FILE_MACHINE_AMD64, IMAGE_FILE_MACHINE_ARM
, IMAGE_FILE_MACHINE_ARM64, IMAGE_FILE_MACHINE_ARMNT, IMAGE_FILE_MACHINE_EBC, IMAGE_FILE_MACHINE_I386, IMAGE_FILE_MACHINE_IA64
, IMAGE_FILE_MACHINE_LOONGARCH32, IMAGE_FILE_MACHINE_LOONGARCH64, IMAGE_FILE_MACHINE_M32R, IMAGE_FILE_MACHINE_MIPS16
, IMAGE_FILE_MACHINE_MIPSFPU, IMAGE_FILE_MACHINE_MIPSFPU16, IMAGE_FILE_MACHINE_POWERRPC, IMAGE_FILE_MACHINE_POWERPCFP
, IMAGE_FILE_MACHINE_R4000, IMAGE_FILE_MACHINE_RISCV32, IMAGE_FILE_MACHINE_RISCV64, IMAGE_FILE_MACHINE_RISCV128, IMAGE_FILE_MACHINE_SH3
, IMAGE_FILE_MACHINE_SH3DSP, IMAGE_FILE_MACHINE_SH4, IMAGE_FILE_MACHINE_SH5, IMAGE_FILE_MACHINE_THUMB, IMAGE_FILE_MACHINE_WCEMIPSV2
};

int OptionalHeaderDllCharacteristics[] = { IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA ,IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE 
,IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY ,IMAGE_DLLCHARACTERISTICS_NX_COMPAT ,IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
,IMAGE_DLLCHARACTERISTICS_NO_SEH ,IMAGE_DLLCHARACTERISTICS_NO_BIND ,IMAGE_DLL_CHARACTERISTICS_APPCONTAINER 
,IMAGE_DLLCHARACTERISTICS_WDM_DRIVER ,IMAGE_DLL_CHARACTERISTICS_GUARD_CF ,IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE };

int SectionHeaderCharacteristics[] = { IMAGE_SCN_TYPE_NO_PAD,IMAGE_SCN_CNT_CODE,IMAGE_SCN_CNT_INITIALIZED_DATA,IMAGE_SCN_CNT_UNINITIALIZED_DATA,IMAGE_SCN_LNK_OTHER
,IMAGE_SCN_LNK_INFO,IMAGE_SCN_LNK_REMOVE,IMAGE_SCN_LNK_COMDAT,IMAGE_SCN_GPREL,IMAGE_SCN_ALIGN_1BYTES,IMAGE_SCN_ALIGN_2BYTES,IMAGE_SCN_ALIGN_4BYTES,IMAGE_SCN_ALIGN_8BYTES
,IMAGE_SCN_ALIGN_16BYTES,IMAGE_SCN_ALIGN_32BYTES,IMAGE_SCN_ALIGN_64BYTES,IMAGE_SCN_ALIGN_128BYTES,IMAGE_SCN_ALIGN_256BYTES,IMAGE_SCN_ALIGN_512BYTES,IMAGE_SCN_ALIGN_1024BYTES
,IMAGE_SCN_ALIGN_2048BYTES,IMAGE_SCN_ALIGN_4096BYTES,IMAGE_SCN_ALIGN_8192BYTES,IMAGE_SCN_LNK_NRELOC_OVFL,IMAGE_SCN_MEM_DISCARDALBE,IMAGE_SCN_MEM_NOT_CACHED,IMAGE_SCN_MEM_NOT_PAGED
,IMAGE_SCN_MEM_SHARED,IMAGE_SCN_MEM_EXECUTE,IMAGE_SCN_MEM_READ,IMAGE_SCN_MEM_WRITE };

unsigned char* FileHeaderCharacteristicsMsg[] = { "IMAGE_FILE_RELOCS_STRIPPED" , "IMAGE_FILE_EXECUTABLE_IMAGE" ,"IMAGE_FILE_LINE_NUMS_STRIPPED"
,"IMAGE_FILE_LOCAL_SYMS_STRIPPED" ,"IMAGE_FILE_AFFRESIVE_WS_TRIM","IMAGE_FILE_LARGE_ADDRESS_AWARE","IMAGE_FILE_BYTES_REVERSED_LO"
,"IMAGE_FILE_32BIT_MACHINE", "IMAGE_FILE_DEBUG_STRIPPED", "IMAGE_FILE_REMOVEABLE_RUN_FROM_SWAP", "IMAGE_FILE_NET_RUM_FROM_SWAP"
,"IMAGE_FILE_SYSTEM" ,"IMAGE_FILE_DLL" ,"IMAGE_FILE_UP_SYSTEM_ONLY" ,"IMAGE_FILE_BYTES_REVERSED_HI" };

unsigned char* FileHeaderMachineMsg[] = { "IMAGE_FILE_MACHINE_UNKNOWN","IMAGE_FILE_MACHINE_AM33","IMAGE_FILE_MACHINE_AMD64"
,"IMAGE_FILE_MACHINE_ARM","IMAGE_FILE_MACHINE_ARM64","IMAGE_FILE_MACHINE_ARMNT","IMAGE_FILE_MACHINE_EBC","IMAGE_FILE_MACHINE_I386"
,"IMAGE_FILE_MACHINE_IA64","IMAGE_FILE_MACHINE_LOONGARCH32","IMAGE_FILE_MACHINE_LOONGARCH64","IMAGE_FILE_MACHINE_M32R"
,"IMAGE_FILE_MACHINE_MIPS16","IMAGE_FILE_MACHINE_MIPSFPU","IMAGE_FILE_MACHINE_MIPSFPU16","IMAGE_FILE_MACHINE_POWERRPC"
,"IMAGE_FILE_MACHINE_POWERPCFP","IMAGE_FILE_MACHINE_R4000","IMAGE_FILE_MACHINE_RISCV32","IMAGE_FILE_MACHINE_RISCV64"
,"IMAGE_FILE_MACHINE_RISCV128","IMAGE_FILE_MACHINE_SH3","IMAGE_FILE_MACHINE_SH3DSP","IMAGE_FILE_MACHINE_SH4","IMAGE_FILE_MACHINE_SH5"
,"IMAGE_FILE_MACHINE_THUMB","IMAGE_FILE_MACHINE_WCEMIPSV2" };

unsigned char* OptionalHeaderDllCharacteristicsMsg[] = { "IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA","IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE"
,"IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY" ,"IMAGE_DLLCHARACTERISTICS_NX_COMPAT" ,"IMAGE_DLLCHARACTERISTICS_NO_ISOLATION"
,"IMAGE_DLLCHARACTERISTICS_NO_SEH" ,"IMAGE_DLLCHARACTERISTICS_NO_BIND" ,"IMAGE_DLL_CHARACTERISTICS_APPCONTAINER"
,"IMAGE_DLLCHARACTERISTICS_WDM_DRIVER" ,"IMAGE_DLL_CHARACTERISTICS_GUARD_CF" ,"IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE" };

unsigned char* SectionHeaderCharacteristicsMsg[] = { "IMAGE_SCN_TYPE_NO_PAD","IMAGE_SCN_CNT_CODE","IMAGE_SCN_CNT_INITIALIZED_DATA","IMAGE_SCN_CNT_UNINITIALIZED_DATA","IMAGE_SCN_LNK_OTHER"
,"IMAGE_SCN_LNK_INFO","IMAGE_SCN_LNK_REMOVE","IMAGE_SCN_LNK_COMDAT","IMAGE_SCN_GPREL","IMAGE_SCN_ALIGN_1BYTES","IMAGE_SCN_ALIGN_2BYTES","IMAGE_SCN_ALIGN_4BYTES","IMAGE_SCN_ALIGN_8BYTES"
,"IMAGE_SCN_ALIGN_16BYTES","IMAGE_SCN_ALIGN_32BYTES","IMAGE_SCN_ALIGN_64BYTES","IMAGE_SCN_ALIGN_128BYTES","IMAGE_SCN_ALIGN_256BYTES","IMAGE_SCN_ALIGN_512BYTES","IMAGE_SCN_ALIGN_1024BYTES"
,"IMAGE_SCN_ALIGN_2048BYTES","IMAGE_SCN_ALIGN_4096BYTES","IMAGE_SCN_ALIGN_8192BYTES","IMAGE_SCN_LNK_NRELOC_OVFL","IMAGE_SCN_MEM_DISCARDALBE","IMAGE_SCN_MEM_NOT_CACHED","IMAGE_SCN_MEM_NOT_PAGED"
,"IMAGE_SCN_MEM_SHARED","IMAGE_SCN_MEM_EXECUTE","IMAGE_SCN_MEM_READ","IMAGE_SCN_MEM_WRITE" };

void CheckCharacteristicsFileHeader(WORD ch) {
	for (int i = 0; i < 15; i++) {
		if ((ch & FileHeaderCharacteristics[i]) == FileHeaderCharacteristics[i]) {
			printf("\t\t\t\t\t- %s\n", FileHeaderCharacteristicsMsg[i]);
		}
	}
}

void CheckMachineFileHeader(WORD m) {
	for (int i = 0; i < 27; i++) {
		if (m == FileHeaderMachine[i]) {
			printf("\t\t\t\t\t- %s\n", FileHeaderMachineMsg[i]);
		}
	}
}

void CheckDllCharacteristicsOptionalHeader(WORD ch) {
	for (int i = 0; i < 11; i++) {
		if ((ch & OptionalHeaderDllCharacteristics[i]) == OptionalHeaderDllCharacteristics[i]) {
			printf("\t\t\t\t\t- %s\n", OptionalHeaderDllCharacteristicsMsg[i]);
		}
	}
}

void CheckCharacteristiceSectionHeaders(DWORD ch) {
	for (int i = 0; i < 31; i++) {
		if ((ch & SectionHeaderCharacteristics[i]) == SectionHeaderCharacteristics[i]) {
			printf("\t\t\t\t\t- %s\n", SectionHeaderCharacteristicsMsg[i]);
		}
	}
}