#include <stdio.h>
#include "structures.h"

typedef void (WINAPI* exit_process)(UINT);

int main()
{

    wchar_t dll_name[] = L"kernel32.dll";
    char api_name[] = "ExitProcess";

    unsigned char* dll_addr = find_dll_addr(dll_name);
    PE pe(dll_addr);
    // pe.iterate_section_names();
    unsigned char* api_name_addr = pe.api_addr(api_name);
    exit_process f_exit_process = (exit_process)api_name_addr;
    f_exit_process(0);
    
    return 0;
}


