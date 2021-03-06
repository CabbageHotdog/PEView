#define _CRT_SECURE_NO_WARNINGS 

#include<stdio.h>
#include<stdlib.h> 
#include<time.h> // 프로그램 동작 시간을 측정하기 위한 헤더파일
#include<io.h> // access 함수를 사용하기 위한 헤더파일
#include<string.h> // 문자열 자르기를 위한 헤더파일
#include"headerinfo.h"
//C:\Users\ss776\Desktop\실습예제\02_PE_File_Format\13_PE_File_Format\bin\notepad.exe

void SetProgramBit(FILE* f);
void SetImageDosHeader(FILE* f);
void SetImageNTHeader(FILE* f);
void SetImageSectionHeader(FILE* f);
void SetImageImportDescriptor(FILE* f);
int MZSignatureCheck(FILE* f);
void PrintImageDosHeader(FILE* fp, OPTION option);
void PrintDOSStub(FILE* fp, OPTION option);
void PrintImageNTHeader(FILE* fp, OPTION option);
void PrintImageFileHeader(FILE* fp, OPTION option);
void PrintImageOptionalHeader(FILE* fp, OPTION option);
void PrintImageSectionHeader(FILE* fp, OPTION option);
void PrintImportDirectoryTable(FILE* fp, OPTION option);
void PrintImportNameTable(FILE* fp, OPTION option);
void PrintMainPoint(OPTION option);
void PrintRawData(FILE* fp, int startoffset, int size, OPTION option);
void PrintOptions(OPTION option);
char GetOption(char* o);
int GetFileSize(FILE* fp);
void InitOptions(OPTION* options);
void SetOptions(OPTION* options, int argc, char* argv[]);
void PrintLine(OPTION option);
__int64 RVAtoRAW(__int64 rva);

unsigned int Machine = 0;
LONG NTHeaderOffset = 0;
IMAGE_DOS_HEADER Image_Dos_Header = { 0, };
IMAGE_NT_HEADERS32 Image_NT_Header = { 0, };
IMAGE_SECTION_HEADER *Image_Section_Header;
IMAGE_IMPORT_DESCRIPTOR* Image_Import_Descriptor;
unsigned char* vmodmsg[3] = { "RawData", "Data\t\tDescription", "Data\t\tValue (Hint) (Name)"};
unsigned char* amodmsg[3] = { "pFile", "VA", "RVA" };
unsigned char* dmodmsg[] = { "Image DOS Header", "DOS Stub", "Image NT Header", "Image File Header", "Image Optional Header" , "Image Section Header"
, "Image Directory Table", "Import Name Table"};
unsigned char* DataDirectoryMsg[16] = { "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
"DEBUG", "COPYRIGHT", "GLOBALPTR", "TLS", "LOAD_CONFIG", "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR",
"Reserved" };
char DisplayCount = -1;
char* filename;
//char* ImageDosHeaderStr[] = { "Signature", "Bytes on last Page of file", "Pages in file", "Relocations", "Size of header in paragraphs", 
//"Minimum extra paragraph needed", "Maximum extra paragraph needed", "Initial (relative) SS value", "Initial SP value", "Checksum", 
//"Initial IP value", "Initial (relative) CS value", "File address of relocation table", "Overlay number", "Reserved", "Reserved","Reserved","Reserved",
//"OEM identifier (for e_oeminfo)", "OEM information; e_oemid specific", "Reserved", "Reserved", "Reserved", "Reserved", "Reserved"
//, "Reserved", "Reserved", "Reserved", "Reserved", "Reserved", "File address of new exe header" };

// 표시할 것들
// -A : All						(0)
// -D : DOSHeader				(1)
// -d : DOSStub					(2)
// -N : NTHeader				(3)
// -F : FileHeader				(4)
// -O : OptionalHeader			(5)
// -S : SectionHeader			(6)
// -Z : Import Directory Table	(7)
// -X : Import Name Table		(8)

// 주소 표시
// -f : 파일 오프셋으로 표시		(0)
// -v : VA로 표시				(1)
// -r : RVA로 표시				(2)

// 표시 방법
// -R : Raw Data				(0)
// -V : View					(1)
// -M : Main point				(2)
// -? : Help					(3)

void PrintLine(OPTION option) {
	if (option.display == DISPLAY_ALL) {
		DisplayCount++;
		if (DisplayCount == 3) {
			DisplayCount += 2;
		}
		if (DisplayCount == 0) {
			printf("%s\n", filename);
		}
	}
	else {
		DisplayCount = option.display - 1;
		printf("%s - ", filename);
	}
	printf("%s\n", dmodmsg[DisplayCount]);
	if (DisplayCount + 1 != DISPLAY_IMPORT_NAME_TABLE) {
		printf("%s\n%s\t\t%s\n%s\n", LINE, amodmsg[option.Address_mod], vmodmsg[option.View_mod], LINE);
	}
	else {
		printf("%s\n%s\t\t%s\n%s\n", LINE, amodmsg[option.Address_mod], vmodmsg[2], LINE);
	}
}

void SetProgramBit(FILE* f) {
	// NT Header Offset 값 저장
	fseek(f, 0x3c, SEEK_SET);
	fread(&NTHeaderOffset, sizeof(NTHeaderOffset), 1, f);
	// printf("NT Header Offset : %08X\n", NTHeaderOffset);

	// NT Header의 Machine값 저장
	fseek(f, NTHeaderOffset + 4, SEEK_SET);
	fread(&Machine, sizeof(WORD), 1, f);
	// printf("Program Bit : %04X\n", ProgramBit);
}

void SetImageDosHeader(FILE* f) {
	fseek(f, 0, SEEK_SET);
	fread(&Image_Dos_Header, sizeof(Image_Dos_Header), 1, f);
}

void SetImageNTHeader(FILE* f) {
	fseek(f, NTHeaderOffset, SEEK_SET);
	fread(&Image_NT_Header, sizeof(Image_NT_Header), 1, f);
}

void SetImageSectionHeader(FILE* f) {
	int NumberOfSection = Image_NT_Header.FileHeader.NumberOfSections;
	Image_Section_Header = (IMAGE_SECTION_HEADER*)malloc(sizeof(IMAGE_SECTION_HEADER) * NumberOfSection);
	fread(Image_Section_Header, sizeof(IMAGE_SECTION_HEADER), NumberOfSection, f);
}

void SetImageImportDescriptor(FILE* f) {
	int addr = Image_NT_Header.OptionalHeader.DataDirectory[1].VirtualAddress;
	int NumberOfImportDescriptor = Image_NT_Header.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	addr = RVAtoRAW(addr);
	Image_Import_Descriptor = (IMAGE_IMPORT_DESCRIPTOR*)malloc(sizeof(IMAGE_IMPORT_DESCRIPTOR) * NumberOfImportDescriptor);
	fseek(f, addr, SEEK_SET);
	fread(Image_Import_Descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), NumberOfImportDescriptor, f);
}

// 나중에 헤더 파일로 뺄 함수임
int MZSignatureCheck(FILE* f) {
	WORD mz;
	fseek(f, 0, SEEK_SET);
	fread(&mz, sizeof(WORD), 1, f);
	fseek(f, 0, SEEK_SET);
	if (mz == 0x5a4d) {
		return 1;
	}
	else {
		return 0;
	}
}

void PrintImageDosHeader(FILE* fp, OPTION option) {
	if (option.display != DISPLAY_DOS_HEADER && option.display != DISPLAY_ALL) {
		return;
	}
	char* std_offset = (char*)&Image_Dos_Header;
	int start_offset = 0;
	PrintLine(option);
	if (option.View_mod == VIEW_MOD_RAW_DATA) {
		PrintRawData(fp, start_offset, sizeof(Image_Dos_Header), option);
	}
	else if (option.View_mod == VIEW_MOD_VALUE) {
		printf("%08I64X\t%04X\t\tSignature\n", (char*)&Image_Dos_Header.e_magic - std_offset, Image_Dos_Header.e_magic);
		printf("%08I64X\t%04X\t\tBytes on last Page of file\n", (char*)&Image_Dos_Header.e_cblp - std_offset, Image_Dos_Header.e_cblp);
		printf("%08I64X\t%04X\t\tPages in file\n", (char*)&Image_Dos_Header.e_cp - std_offset, Image_Dos_Header.e_cp);
		printf("%08I64X\t%04X\t\tRelocations\n", (char*)&Image_Dos_Header.e_crlc - std_offset, Image_Dos_Header.e_crlc);
		printf("%08I64X\t%04X\t\tSize of header in paragraphs\n", (char*)&Image_Dos_Header.e_cparhdr - std_offset, Image_Dos_Header.e_cparhdr);
		printf("%08I64X\t%04X\t\tMinimum extra paragraph needed\n", (char*)&Image_Dos_Header.e_minalloc - std_offset, Image_Dos_Header.e_minalloc);
		printf("%08I64X\t%04X\t\tMaximum extra paragraph needed\n", (char*)&Image_Dos_Header.e_maxalloc - std_offset, Image_Dos_Header.e_maxalloc);
		printf("%08I64X\t%04X\t\tInitial (relative) SS value\n", (char*)&Image_Dos_Header.e_ss - std_offset, Image_Dos_Header.e_ss);
		printf("%08I64X\t%04X\t\tInitial SP value\n", (char*)&Image_Dos_Header.e_sp - std_offset, Image_Dos_Header.e_sp);
		printf("%08I64X\t%04X\t\tChecksum\n", (char*)&Image_Dos_Header.e_csum - std_offset, Image_Dos_Header.e_csum);
		printf("%08I64X\t%04X\t\tInitial IP value\n", (char*)&Image_Dos_Header.e_ip - std_offset, Image_Dos_Header.e_ip);
		printf("%08I64X\t%04X\t\tInitial (relative) CS value\n", (char*)&Image_Dos_Header.e_cs - std_offset, Image_Dos_Header.e_cs);
		printf("%08I64X\t%04X\t\tFile address of relocation table\n", (char*)&Image_Dos_Header.e_lfarlc - std_offset, Image_Dos_Header.e_lfarlc);
		printf("%08I64X\t%04X\t\tOverlay number\n", (char*)&Image_Dos_Header.e_ovno - std_offset, Image_Dos_Header.e_ovno);
		for (int i = 0; i < 4; i++) {
			printf("%08I64X\t%04X\t\tReserved\n", (char*)&Image_Dos_Header.e_res[i] - std_offset, Image_Dos_Header.e_res[i]);
		}
		printf("%08I64X\t%04X\t\tOEM identifier (for e_oeminfo)\n", (char*)&Image_Dos_Header.e_oemid - std_offset, Image_Dos_Header.e_oemid);
		printf("%08I64X\t%04X\t\tOEM information; e_oemid specific\n", (char*)&Image_Dos_Header.e_oeminfo - std_offset, Image_Dos_Header.e_oeminfo);
		for (int i = 0; i < 10; i++) {
			printf("%08I64X\t%04X\t\tReserved\n", (char*)&Image_Dos_Header.e_res2[i] - std_offset, Image_Dos_Header.e_res2[i]);
		}
		printf("%08I64X\t%08X\tFile address of new exe header\n", (char*)&Image_Dos_Header.e_lfanew - std_offset, Image_Dos_Header.e_lfanew);

	}

	printf("\n\n");
}

void PrintDOSStub(FILE* fp, OPTION option) {
	OPTION DOSStubOption = option;
	DOSStubOption.View_mod = 0;
	if (option.display != DISPLAY_DOS_STUB && option.display != DISPLAY_ALL) {
		return;
	}
	int DosStubSize = NTHeaderOffset - 0x40;
	PrintLine(DOSStubOption);
	PrintRawData(fp, 0x40, DosStubSize, DOSStubOption);

	printf("\n\n");
}

void PrintImageNTHeader(FILE* fp, OPTION option) {
	if (option.display != DISPLAY_NT_HEADER && option.display != DISPLAY_ALL) {
		return;
	}
	char* std_offset = (char*)&Image_NT_Header;
	int start_offset = Image_Dos_Header.e_lfanew;

	PrintLine(option);
	if (option.View_mod == VIEW_MOD_RAW_DATA) {
		PrintRawData(fp, start_offset, sizeof(Image_NT_Header), option);
	}
	else if (option.View_mod == VIEW_MOD_VALUE) {
		// IMAGE_NT_HEADER의 Signature 출력
		printf("%08I64X\t%08X\tSignature\n", start_offset + (char*)&Image_NT_Header.Signature - std_offset, Image_Dos_Header.e_magic);
		printf("\n\n");

		// IMAGE_FILE_HEADER 출력
		option.display = 4;
		PrintImageFileHeader(fp, option);

		// IMAGE_OPTIONAL_HEADER 출력
		option.display = 5;
		PrintImageOptionalHeader(fp, option);

	}

	printf("\n\n");
}

void PrintImageFileHeader(FILE* fp, OPTION option) {
	if (option.display != DISPLAY_FILE_HEADER) {
		return;
	}
	char* std_offset = (char*)&Image_NT_Header.FileHeader;
	int start_offset = Image_Dos_Header.e_lfanew + 4;

	PrintLine(option);
	if (option.View_mod == VIEW_MOD_RAW_DATA) {
		PrintRawData(fp, start_offset, sizeof(Image_NT_Header.FileHeader), option);
	}
	else if (option.View_mod == VIEW_MOD_VALUE) {
		printf("%08I64X\t%04X\t\tMachine\n", start_offset + (char*)&Image_NT_Header.FileHeader.Machine - std_offset, Image_NT_Header.FileHeader.Machine);
		CheckMachineFileHeader(Image_NT_Header.FileHeader.Machine);
		printf("%08I64X\t%04X\t\tNumber of Section\n", start_offset + (char*)&Image_NT_Header.FileHeader.NumberOfSections - std_offset, Image_NT_Header.FileHeader.NumberOfSections);
		printf("%08I64X\t%08X\tTime Date Stamp\n", start_offset + (char*)&Image_NT_Header.FileHeader.TimeDateStamp - std_offset, Image_NT_Header.FileHeader.TimeDateStamp);
		printf("%08I64X\t%08X\tPointer ot Symbol Table\n", start_offset + (char*)&Image_NT_Header.FileHeader.PointerToSymbolTable - std_offset, Image_NT_Header.FileHeader.PointerToSymbolTable);
		printf("%08I64X\t%08X\tNumber of Sysbols\n", start_offset + (char*)&Image_NT_Header.FileHeader.NumberOfSymbols - std_offset, Image_NT_Header.FileHeader.NumberOfSymbols);
		printf("%08I64X\t%04X\t\tSize of Optional Header\n", start_offset + (char*)&Image_NT_Header.FileHeader.SizeOfOptionalHeader - std_offset, Image_NT_Header.FileHeader.SizeOfOptionalHeader);
		printf("%08I64X\t%04X\t\tCharacteristics\n", start_offset + (char*)&Image_NT_Header.FileHeader.Characteristics - std_offset, Image_NT_Header.FileHeader.Characteristics);
		CheckCharacteristicsFileHeader(Image_NT_Header.FileHeader.Characteristics);
	}

	printf("\n\n");
}

void PrintImageOptionalHeader(FILE* fp, OPTION option) {
	if (option.display != DISPLAY_OPTIONAL_HEADER) {
		return;
	}
	char* std_offset = (char*)&Image_NT_Header.OptionalHeader;
	int start_offset = Image_Dos_Header.e_lfanew + 4 + sizeof(Image_NT_Header.FileHeader);

	PrintLine(option);
	if (option.View_mod == VIEW_MOD_RAW_DATA) {
		PrintRawData(fp, start_offset, sizeof(Image_NT_Header.OptionalHeader), option);
	}
	else if (option.View_mod == VIEW_MOD_VALUE) {
		printf("%08I64X\t%04X\t\tMagic\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.Magic - std_offset, Image_NT_Header.OptionalHeader.Magic);
		printf("%08I64X\t%02X\t\tMajor Linker Version\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.MajorLinkerVersion - std_offset, Image_NT_Header.OptionalHeader.MajorLinkerVersion);
		printf("%08I64X\t%02X\t\tMinor Linker Version\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.MinorLinkerVersion - std_offset, Image_NT_Header.OptionalHeader.MinorLinkerVersion);
		printf("%08I64X\t%08X\tSize of Code\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SizeOfCode - std_offset, Image_NT_Header.OptionalHeader.SizeOfCode);
		printf("%08I64X\t%08X\tSize of Initialized Data\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SizeOfInitializedData - std_offset, Image_NT_Header.OptionalHeader.SizeOfInitializedData);
		printf("%08I64X\t%08X\tSize of Uninitialized Data\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SizeOfUninitializedData - std_offset, Image_NT_Header.OptionalHeader.SizeOfUninitializedData);
		printf("%08I64X\t%08X\tAddress of Entry Point\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.AddressOfEntryPoint - std_offset, Image_NT_Header.OptionalHeader.AddressOfEntryPoint);
		printf("%08I64X\t%08X\tBase of Code\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.BaseOfCode - std_offset, Image_NT_Header.OptionalHeader.BaseOfCode);
		printf("%08I64X\t%08X\tBase of Data\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.BaseOfData - std_offset, Image_NT_Header.OptionalHeader.BaseOfData);
		printf("%08I64X\t%08X\tImage Base\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.ImageBase - std_offset, Image_NT_Header.OptionalHeader.ImageBase);
		printf("%08I64X\t%08X\tSection Alignment\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SectionAlignment - std_offset, Image_NT_Header.OptionalHeader.SectionAlignment);
		printf("%08I64X\t%08X\tFile Alignment\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.FileAlignment - std_offset, Image_NT_Header.OptionalHeader.FileAlignment);
		printf("%08I64X\t%04X\t\tMajor O/S Version\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.MajorOperatingSystemVersion - std_offset, Image_NT_Header.OptionalHeader.MajorOperatingSystemVersion);
		printf("%08I64X\t%04X\t\tMinor O/S Version\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.MinorOperatingSystemVersion - std_offset, Image_NT_Header.OptionalHeader.MinorOperatingSystemVersion);
		printf("%08I64X\t%04X\t\tMajor Image Version\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.MajorImageVersion - std_offset, Image_NT_Header.OptionalHeader.MajorImageVersion);
		printf("%08I64X\t%04X\t\tMinor Image Version\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.MinorImageVersion - std_offset, Image_NT_Header.OptionalHeader.MinorImageVersion);
		printf("%08I64X\t%04X\t\tMajor Subsystem Version\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.MajorSubsystemVersion - std_offset, Image_NT_Header.OptionalHeader.MajorSubsystemVersion);
		printf("%08I64X\t%04X\t\tMinor Subsystem Version\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.MinorSubsystemVersion - std_offset, Image_NT_Header.OptionalHeader.MinorSubsystemVersion);
		printf("%08I64X\t%08X\tWin32 Version Value\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.Win32VersionValue - std_offset, Image_NT_Header.OptionalHeader.Win32VersionValue);
		printf("%08I64X\t%08X\tSize of Image\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SizeOfImage - std_offset, Image_NT_Header.OptionalHeader.SizeOfImage);
		printf("%08I64X\t%08X\tSize of Headers\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SizeOfHeaders - std_offset, Image_NT_Header.OptionalHeader.SizeOfHeaders);
		printf("%08I64X\t%08X\tChecksum\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.CheckSum - std_offset, Image_NT_Header.OptionalHeader.CheckSum);
		printf("%08I64X\t%04X\t\tSubsystem\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.Subsystem - std_offset, Image_NT_Header.OptionalHeader.Subsystem);
		printf("%08I64X\t%04X\t\tDLL Characteristics\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.DllCharacteristics - std_offset, Image_NT_Header.OptionalHeader.DllCharacteristics);
		CheckDllCharacteristicsOptionalHeader(Image_NT_Header.OptionalHeader.DllCharacteristics);
		printf("%08I64X\t%08X\tSize of Stack Reserve\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SizeOfStackReserve - std_offset, Image_NT_Header.OptionalHeader.SizeOfStackReserve);
		printf("%08I64X\t%08X\tSize of Stack Commit\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SizeOfStackCommit - std_offset, Image_NT_Header.OptionalHeader.SizeOfStackCommit);
		printf("%08I64X\t%08X\tSize of Heap Reserve\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SizeOfHeapReserve - std_offset, Image_NT_Header.OptionalHeader.SizeOfHeapReserve);
		printf("%08I64X\t%08X\tSize of Heap Commit\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.SizeOfHeapCommit - std_offset, Image_NT_Header.OptionalHeader.SizeOfHeapCommit);
		printf("%08I64X\t%08X\tLoader Flags\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.LoaderFlags - std_offset, Image_NT_Header.OptionalHeader.LoaderFlags);
		printf("%08I64X\t%08X\tNumber of Data Directories\n", start_offset + (char*)&Image_NT_Header.OptionalHeader.NumberOfRvaAndSizes - std_offset, Image_NT_Header.OptionalHeader.NumberOfRvaAndSizes);
		for (int i = 0; i < 16; i++) {
			printf("%08I64X\t%08X\t", start_offset + (char*)&Image_NT_Header.OptionalHeader.DataDirectory[i] - std_offset, Image_NT_Header.OptionalHeader.DataDirectory[i].VirtualAddress);
			printf("RVA  of %s Directory\n", DataDirectoryMsg[i]);
			printf("%08I64X\t%08X\t", start_offset + (char*)&Image_NT_Header.OptionalHeader.DataDirectory[i] - std_offset + 4, Image_NT_Header.OptionalHeader.DataDirectory[i].Size);
			printf("size of %s Directory\n", DataDirectoryMsg[i]);
		}
	}

	printf("\n\n");
}

void PrintImageSectionHeader(FILE* fp, OPTION option) {
	if (option.display != DISPLAY_SECTION_HEADER && option.display != DISPLAY_ALL) {
		return;
	}
	char* std_offset = (char*)Image_Section_Header;
	int start_offset = Image_Dos_Header.e_lfanew + 4 + sizeof(Image_NT_Header.FileHeader) + Image_NT_Header.FileHeader.SizeOfOptionalHeader;
	int NumberOfSection = Image_NT_Header.FileHeader.NumberOfSections;
	PrintLine(option);
	if (option.View_mod == VIEW_MOD_RAW_DATA) {
		PrintRawData(fp, start_offset, sizeof(IMAGE_SECTION_HEADER) * NumberOfSection, option);
	}
	else if(option.View_mod == VIEW_MOD_VALUE) {
		for (int i = 0; i < NumberOfSection; i++) {
			printf("%08I64X\t", start_offset + (char*)&Image_Section_Header[i].Name - std_offset);
			for (int j = 0; j < 8; j++) {
				printf("%02X", Image_Section_Header[i].Name[j]);
				if (j == 3) {
					printf("\tName - {%s}\n%08I64X\t", Image_Section_Header[i].Name, start_offset + (char*)&Image_Section_Header[i].Name - std_offset+4);
				}
			}
			printf("\n");
			printf("%08I64X\t%08X\tVirtual Size\n", start_offset + (char*)&Image_Section_Header[i].Misc.VirtualSize - std_offset, Image_Section_Header[i].Misc.VirtualSize);
			printf("%08I64X\t%08X\tVirtual Address\n", start_offset + (char*)&Image_Section_Header[i].VirtualAddress - std_offset, Image_Section_Header[i].VirtualAddress);
			printf("%08I64X\t%08X\tSize Of Raw Data\n", start_offset + (char*)&Image_Section_Header[i].SizeOfRawData - std_offset, Image_Section_Header[i].SizeOfRawData);
			printf("%08I64X\t%08X\tPointer To Raw Data\n", start_offset + (char*)&Image_Section_Header[i].PointerToRawData - std_offset, Image_Section_Header[i].PointerToRawData);
			printf("%08I64X\t%08X\tPointer To Relocations\n", start_offset + (char*)&Image_Section_Header[i].PointerToRelocations - std_offset, Image_Section_Header[i].PointerToRelocations);
			printf("%08I64X\t%08X\tPointer To Line Numbers\n", start_offset + (char*)&Image_Section_Header[i].PointerToLinenumbers - std_offset, Image_Section_Header[i].PointerToLinenumbers);
			printf("%08I64X\t%04X\t\tNumber Of Relocations\n", start_offset + (char*)&Image_Section_Header[i].NumberOfRelocations - std_offset, Image_Section_Header[i].NumberOfRelocations);
			printf("%08I64X\t%04X\t\tNumber Of Line Numbers\n", start_offset + (char*)&Image_Section_Header[i].NumberOfLinenumbers - std_offset, Image_Section_Header[i].NumberOfLinenumbers);
			printf("%08I64X\t%08X\tCharacteristics\n", start_offset + (char*)&Image_Section_Header[i].Characteristics - std_offset, Image_Section_Header[i].Characteristics);
			CheckCharacteristiceSectionHeaders(Image_Section_Header[i].Characteristics);
			printf("\n\n");
		}
	}
}

// 임시로 Z 옵션
// pFile 주소 변환 추가
void PrintImportDirectoryTable(FILE* fp, OPTION option) {
	if (option.display != DISPLAY_IMPORT_DIRECTORY_TABLE && option.display != DISPLAY_ALL) {
		return;
	}
	char* std_offset = (char*)Image_Import_Descriptor;
	int start_offset = Image_NT_Header.OptionalHeader.DataDirectory[1].VirtualAddress;
	int name_address;
	char ch = 0;
	if (start_offset >= Image_Section_Header[0].VirtualAddress) {
		start_offset = RVAtoRAW(Image_NT_Header.OptionalHeader.DataDirectory[1].VirtualAddress);
	}
	int NumberOfImportDescriptor = Image_NT_Header.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	PrintLine(option);
	if (option.View_mod == VIEW_MOD_RAW_DATA) {
		PrintRawData(fp, start_offset, Image_NT_Header.OptionalHeader.DataDirectory[1].Size, option);
	}
	else if (option.View_mod == VIEW_MOD_VALUE) {
		for (int i = 0; i < NumberOfImportDescriptor - 1; i++) {
			printf("%08I64X\t%08X\tImport Name Table RVA\n", start_offset + (char*)&Image_Import_Descriptor[i].OriginalFirstThunk - std_offset, Image_Import_Descriptor[i].OriginalFirstThunk);
			printf("%08I64X\t%08X\tTime Data Stamp\n", start_offset + (char*)&Image_Import_Descriptor[i].TimeDataStamp - std_offset, Image_Import_Descriptor[i].TimeDataStamp);
			printf("%08I64X\t%08X\tForwarder Chain\n", start_offset + (char*)&Image_Import_Descriptor[i].ForwarderChain - std_offset, Image_Import_Descriptor[i].ForwarderChain);
			printf("%08I64X\t%08X\tName RVA (", start_offset + (char*)&Image_Import_Descriptor[i].Name - std_offset, Image_Import_Descriptor[i].Name);
			name_address = RVAtoRAW(Image_Import_Descriptor[i].Name);
			fseek(fp, name_address, SEEK_SET);
			while (1) {
				ch = fgetc(fp);
				if (ch == NULL) {
					break;
				}
				printf("%c", ch);
			}
			printf(")\n");
			printf("%08I64X\t%08X\tImport Address Table RVA\n", start_offset + (char*)&Image_Import_Descriptor[i].FirstThunk - std_offset, Image_Import_Descriptor[i].FirstThunk);
			printf("\n\n");
		}
	}
}

void PrintImportNameTable(FILE* fp, OPTION option) {
	if (option.display != DISPLAY_IMPORT_NAME_TABLE && option.display != DISPLAY_ALL) {
		return;
	}
	int NumberOfImportDescriptor = Image_NT_Header.OptionalHeader.DataDirectory[1].Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	DWORD ImportNameTableAddress = RVAtoRAW(Image_Import_Descriptor[0].OriginalFirstThunk);
	WORD Hint;
	char ch;
	DWORD NameAddress;
	
	PrintLine(option);
	for (int i = 0; i < NumberOfImportDescriptor; i++) {
		ImportNameTableAddress = RVAtoRAW(Image_Import_Descriptor[i].OriginalFirstThunk);
		while (1) {
			fseek(fp, ImportNameTableAddress, SEEK_SET);
			fread(&NameAddress, sizeof(DWORD), 1, fp);
			if (NameAddress == NULL) {
				break;
			}
			printf("%08X\t%08X\t", ImportNameTableAddress, NameAddress);
			NameAddress = RVAtoRAW(NameAddress);
			fseek(fp, NameAddress, SEEK_SET);
			fread(&Hint, sizeof(WORD), 1, fp);
			printf("%04X ", Hint);
			while (1) {
				ch = fgetc(fp);
				if (ch == NULL) {
					break;
				}
				printf("%c", ch);
			}
			printf("\n");
			ImportNameTableAddress += 4;
		}
		printf("\n");
	}

	printf("\n");
	
}

// 출력할 것들
// entry point(rva)
// entry point(raw)
// Image base
// size of image
// sections alignment
// file alignment
// number of section
// dll characteristics
void PrintMainPoint(OPTION option) {
	
}

// 50000바이트 기준 약 1.5초
void PrintRawData(FILE* fp, int startoffset, int size, OPTION option) {
	unsigned char* buf = (char*)malloc(sizeof(char) * size);
	unsigned char tempstr[48] = { 0, };

	fseek(fp, startoffset, SEEK_SET);
	fread(buf, size, 1, fp);
	for (int i = 0; i < size; i++) {
		if (i % 16 == 0) {
			printf("%08X\t", startoffset + i);
		}
		sprintf(&tempstr[(i * 3) % 48], "%02X", buf[i]);
		tempstr[(i * 3) % 48 + 2] = ' ';
		if (i == size - 1 || i % 16 == 15) {
			tempstr[(i * 3) % 48 + 2] = NULL;
			printf("%s\n", tempstr);
		}
	}
	free(buf);
}

void PrintOptions(OPTION option) {
	if (option.View_mod != VIEW_MOD_HELP) {
		return;
	}
	printf("\n\nOptions:\n");
	printf("\tDisplay Options\n");
	printf("\t\t-A\tAll\n");
	printf("\t\t-D\tDOS Header\n");
	printf("\t\t-d\tDOS Stub\n");
	printf("\t\t-N\tNT Header\n");
	printf("\t\t-F\tFile Header\n");
	printf("\t\t-O\tOptional Header\n");
	printf("\t\t-S\tSection Header\n");
	printf("\t\t-C\tSection\n\n");

	printf("\tAddress Options:\n");
	printf("\t\t-f\tFile Offset\n");
	printf("\t\t-v\tVA Offset\n");
	printf("\t\t-r\tRVA Offset\n\n");

	printf("\tView Options:\n");
	printf("\t\t-R\tRaw Data View\n");
	printf("\t\t-V\tValue View\n");
	printf("\t\t-M\tMain Point View\n");
}

char GetOption(char* o) {
	char option;

	option = o[1];

	return option;
}

int GetFileSize(FILE* fp) {
	int size;
	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	return size;
}

void InitOptions(OPTION* options) {
	options->Address_mod = ADDRESS_MOD_FILE_OFFSET;
	options->View_mod = VIEW_MOD_RAW_DATA;
	options->display = DISPLAY_ALL;
}

void SetOptions(OPTION* options, int argc, char* argv[]) {
	char option;
	for (int i = 1; i < argc - 1; i++) {
		option = GetOption(argv[i]);
		switch (option) {
		case 'R':
			options->View_mod = VIEW_MOD_RAW_DATA;
			break;
		case 'V':
			options->View_mod = VIEW_MOD_VALUE;
			break;
		case 'M':
			options->View_mod = VIEW_MOD_MAINPOINT;
			break;
		case '?':
			options->View_mod = VIEW_MOD_HELP;
			break;
		case 'f':
			options->Address_mod = ADDRESS_MOD_FILE_OFFSET;
			break;
		case 'v':
			options->Address_mod = ADDRESS_MOD_VITUAL_ADDRESS;
			break;
		case 'r':
			options->Address_mod = ADDRESS_MOD_RELATIVE_VITUAL_ADDRESS;
			break;
		case 'A':
			options->display = DISPLAY_ALL;
			break;
		case 'D':
			options->display = DISPLAY_DOS_HEADER;
			break;
		case 'd':
			options->display = DISPLAY_DOS_STUB;
			break;
		case 'N':
			options->display = DISPLAY_NT_HEADER;
			break;
		case 'F':
			options->display = DISPLAY_FILE_HEADER;
			break;
		case 'O':
			options->display = DISPLAY_OPTIONAL_HEADER;
			break;
		case 'S':
			options->display = DISPLAY_SECTION_HEADER;
			break;
		case 'Z':
			options->display = DISPLAY_IMPORT_DIRECTORY_TABLE;
			break;
		case 'X':
			options->display = DISPLAY_IMPORT_NAME_TABLE;
			break;
		}
	}

	/*printf("option.Address_mod : %d\n", options->Address_mod);
	printf("option.View_mod : %d\n", options->View_mod);
	printf("option.asdf : %d\n", options->asdf);*/
}

__int64 RVAtoRAW(__int64 rva) {
	__int64 raw;
	int NumberOfSections = Image_NT_Header.FileHeader.NumberOfSections;
	for (int i = 0; i < NumberOfSections; i++) {
		if (Image_Section_Header[i].VirtualAddress < rva && rva < Image_Section_Header[i].VirtualAddress + Image_Section_Header[i].Misc.VirtualSize) {
			raw = rva - Image_Section_Header[i].VirtualAddress + Image_Section_Header[i].PointerToRawData;
			if (Image_Section_Header[i].PointerToRawData < raw && raw < Image_Section_Header[i].PointerToRawData + Image_Section_Header[i].SizeOfRawData) {
				return raw;
			}
			// raw값의 위치가 다른 섹션에 있을 경우
			else {
				return -1;
			}
		}
	}
	return 0;
}


// 표시할 것들
// -A : All						(0)
// -D : DOSHeader				(1)
// -d : DOSStub					(2)
// -N : NTHeader				(3)
// -F : FileHeader				(4)
// -O : OptionalHeader			(5)
// -S : SectionHeader			(6)
// -Z : Import Directory Table	(7)
// -X : Import Name Table		(8)

// 주소 표시
// -f : 파일 오프셋으로 표시		(0)
// -v : VA로 표시				(1)
// -r : RVA로 표시				(2)

// 표시 방법
// -R : Raw Data				(0)
// -V : Value					(1)
// -M : Main point				(2)
// -? : Help					(3)

int main(int argc, char* argv[]) {
	/*clock_t start, end;
	double result;*/
	int size = 0;
	FILE* fp;
	OPTION options;
	char option;

	// 최소 옵션 개수 검사
	if (argc < 2) {
		char* programname = strrchr(argv[0], '\\') + 1;
		printf("Usage : %s [options] path[s]", programname);
		options.View_mod = VIEW_MOD_HELP;
		PrintOptions(options);
		return -1;
	}
	//// 파일 유무 검사
	//if (access(argv[argc - 1], 0)) {
	//	printf("File not found.\n");
	//	return -1;
	//}

	// 옵션 초기화
	InitOptions(&options);

	// 옵션 세팅
	SetOptions(&options, argc, argv);

	// 파일 열기
	fp = fopen(argv[argc - 1], "rb");

	// 파일 열렸나 검사
	if (fp == NULL) {
		printf("Failed to open file\n");
		return -1;
	}

	// MZ Signature 검사
	if (!(MZSignatureCheck(fp))) {
		printf("Not PE File\n");
		return -1;
	}

	// 파일 경로에서 파일 이름 추출
	filename = strrchr(argv[argc - 1], '\\');
	if (!filename) {
		filename = strrchr(argv[argc - 1], '/');
	}
	if (!filename) {
		filename = argv[argc - 1];
	}
	filename++;

	// 파일 크기 저장
	size = GetFileSize(fp);

	PrintOptions(options);

	// 프로그램 비트 세팅
	SetProgramBit(fp);

	// DOS Header 구조체 세팅
	SetImageDosHeader(fp);

	// IMAGE_NT_HEADERS 구조체 세팅
	SetImageNTHeader(fp);

	// IMAGE_SECTION_HEADER 세팅
	SetImageSectionHeader(fp);

	// Import Directory Table 세팅
	SetImageImportDescriptor(fp);

	// DOS Header 출력
	PrintImageDosHeader(fp, options);

	// DOS Stub 출력
	PrintDOSStub(fp, options);

	// IMAGE_NT_HEADERS 출력
	PrintImageNTHeader(fp, options);

	// IMAGE_FILE_HEADER 출력
	PrintImageFileHeader(fp, options);

	// IMAGE_OPTIONAL_HEADER 출력
	PrintImageOptionalHeader(fp, options);

	// IMAGE_SECTION_HEADER 출력
	PrintImageSectionHeader(fp, options);

	// Import Directory Table 출력
	PrintImportDirectoryTable(fp, options);

	// Import Name Table 출력
	PrintImportNameTable(fp, options);


	PrintMainPoint(options);


	/*start = clock();
	PrintRawData(fp, 0, 1000, view_mod);

	end = clock();
	result = (double)(end - start);
	printf("%f", result / CLOCKS_PER_SEC);*/

	fclose(fp);
	return 0;
}