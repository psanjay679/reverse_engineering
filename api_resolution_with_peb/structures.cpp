#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include "structures.h"


unsigned char* find_dll_addr(wchar_t* dll_name) {

    TEB* teb = (TEB*)__readfsdword(offsetof(NT_TIB, Self));

    PEB* peb = (PEB*)(teb->ProcessEnvironmentBlock);
    LIST_ENTRY* module_tail = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* module_head = module_tail->Flink;

    do {
        unsigned char* module_addr = (unsigned char*)module_head - sizeof(LIST_ENTRY);
        ldr_data_table_entry* entry = (ldr_data_table_entry*)module_addr;
        wchar_t name[128];
        memcpy(name, entry->FullDllName.Buffer, 128);
        wchar_t base_name[128];
        //printf("dll_name: %ws\n", name);
        memcpy(base_name, entry->BaseDllName.Buffer, 128);
        //wprintf(L"base_dll_name: %ws\n", base_name);
        wcslwr(dll_name);
        wcslwr(base_name);
        if (wcscmp(dll_name, base_name) == 0) {
            printf("DllBase: %08x\n", entry->DllBase);
            return (unsigned char*)entry->DllBase;
        }
        module_head = module_head->Flink;
    } while (module_head != module_tail);

    return (unsigned char*)0x0;
}

unsigned char* find_api_address(wchar_t* api_name, wchar_t* dll_name) {

    unsigned char* dll_base = find_dll_addr(dll_name);

    IMAGE_DOS_HEADER* pe_image = (IMAGE_DOS_HEADER*)dll_base;
    IMAGE_NT_HEADERS* nt_headers = (IMAGE_NT_HEADERS*)(dll_base + (unsigned char)pe_image->e_lfanew);
    IMAGE_FILE_HEADER* file_header = (IMAGE_FILE_HEADER*)&nt_headers->FileHeader;
    return 0;
}

PE::PE(unsigned char* base_addr) {

    this->base_addr = base_addr;
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)this->base_addr;

    this->nt_header = (IMAGE_NT_HEADERS*)(this->base_addr + dos_header->e_lfanew);
    this->file_header = (IMAGE_FILE_HEADER*)(&this->nt_header->FileHeader);
    this->optional_header = (IMAGE_OPTIONAL_HEADER*)(&this->nt_header->OptionalHeader);

}

void PE::iterate_section_names() {

    DWORD section_addr;
    DWORD base_addr = (DWORD)this->base_addr;
    
    section_addr = (DWORD)this->nt_header + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + (DWORD)this->file_header->SizeOfOptionalHeader;
    
    for (int i = 0; i < this->file_header->NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* section_header = (IMAGE_SECTION_HEADER*)section_addr;
        //printf("section name: %s\n", section_header->Name);
        section_addr += sizeof(IMAGE_SECTION_HEADER);
    }
}

unsigned char* PE::api_addr(char* api_name) {
    
    unsigned char* export_directory_addr = (unsigned char*)this->nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*)(this->base_addr + (DWORD)export_directory_addr);

    int num_functinos = export_directory->NumberOfFunctions;
    //printf("export_dir_addr: %08x\n", export_directory_addr);
    //printf("number of functions: %x\n", num_functinos);


    for (int i = 0; i < num_functinos; i++) {

        DWORD name_ordinal_addr = (DWORD)this->base_addr + export_directory->AddressOfNameOrdinals + 2 * i;
        WORD* name_ordinal_ptr = (WORD*)name_ordinal_addr;

        //printf("name_ordinal_ptr: %x\n", *name_ordinal_ptr);

        DWORD *ptr_func_addr = (DWORD*)((DWORD)this->base_addr + export_directory->AddressOfFunctions + *name_ordinal_ptr * 4);
        
        DWORD* ptr_name_addr = (DWORD*)((DWORD)this->base_addr + export_directory->AddressOfNames + i * 4);

        //printf("name_addr: %08x\tptr_name_addr: %08x\n", ptr_name_addr, *ptr_name_addr);

        CHAR* name_addr = (CHAR*)((DWORD)this->base_addr + *ptr_name_addr);
        DWORD mem_func_addr = (DWORD)((DWORD)this->base_addr + *ptr_func_addr);
        //printf("mem_func_addr: %08x\tptr_func_addr: %08x\tname: %s\n", mem_func_addr, *ptr_func_addr, name_addr);
        //printf("%s\n", name_addr);
        //getchar();

        if (strcmp(api_name, name_addr) == 0) {
            // got the function name
            unsigned char* ret_func_addr = (unsigned char*)((DWORD)this->base_addr + *ptr_func_addr);
            //printf("address of function %s is %08x addr_ptr: %08x\n", api_name, ret_func_addr, *ret_func_addr);
            return (unsigned char*)((DWORD)this->base_addr + *ptr_func_addr);
        }
    }

    return 0;
}
