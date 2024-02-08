#pragma once
#include <windows.h>
#include <winternl.h>

class PE {
	unsigned char* base_addr;
	IMAGE_NT_HEADERS* nt_header;
	IMAGE_FILE_HEADER* file_header;
	IMAGE_OPTIONAL_HEADER* optional_header;
public:
	PE(unsigned char*);
	void iterate_section_names();
	unsigned char* api_addr(char* api_name);
};

typedef struct ldr_data_table_entry {
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;

} ldr_data_table_entry, *pldr_data_table_entry;


unsigned char* find_dll_addr(wchar_t*);
void print_dll_names();