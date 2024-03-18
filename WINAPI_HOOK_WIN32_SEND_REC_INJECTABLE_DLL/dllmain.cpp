//working on hooking send and rec

#include "pch.h"
#include <windows.h>
#include <winsock2.h>
#include <winsock.h>
#include <array>


#include <iostream>
#include <fstream>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

/// Define the prototyps for function pointers
typedef int(WINAPI *Prototypesend)(SOCKET s, const char* buf, int len, int flags);
typedef int(WINAPI *Prototyperecv)(SOCKET s, char *buf,       int len, int flags);

// Pointer to the original functions
//Prototypesend originalsend = send;
//Prototyperecv originalrecv = recv;

Prototypesend originalsend;
Prototyperecv originalrecv;

// Hooked send function
int hookedsend(SOCKET s, const char *buf, int len, int flags)
{
    //modify the data and send
    std::array<char, 8> newbuf = { 0 };
    if (newbuf.at(4) == 0xd1 &&
        newbuf.at(5) == 0x58)
    {
        newbuf.at(6) = 0x01;
    }

    // Call the original send with the modified data
    return originalsend(s, buf, len, flags);
}

// Hooked send function
int hookedrecv(SOCKET s, char *buf, int len, int flags)
{
    ////modify the data and send
    //std::array<char, 8> newbuf = { 0 };
    //for (int x = 0; x < len; ++x)
    //{
    //    newbuf.at(x) = buf[x];
    //    if (x == 6)
    //    {
    //        newbuf.at(6) = 0x0b;
    //    }
    //}

    // Call the original send with the modified data
    return originalrecv(s, buf, len, flags);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    HMODULE hModule = 0;
    DWORD oldProtect = 0;

    PIMAGE_DOS_HEADER pDosHeader;

    // Get the address of the IMAGE_NT_HEADERS
    PIMAGE_NT_HEADERS pNtHeader;

    // Get the address of the IMAGE_IMPORT_DESCRIPTOR
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;

    switch (fdwReason)
    {
         case DLL_PROCESS_ATTACH:
             /////////        /////////        /////////        /////////
             // Get the address of the send function
             originalsend = (Prototypesend)GetProcAddress(GetModuleHandle(TEXT("ws2_32.dll")), "send");
             if (originalsend == NULL)
             {
                 // Error handling
                 return FALSE;
             }

             // Get the address of the recv function
             originalrecv = (Prototyperecv)GetProcAddress(GetModuleHandle(TEXT("wsock32.dll")), "recv");
             if (originalrecv == NULL)
             {
                 // Error handling
                 return FALSE;
             }
             /////////        /////////        /////////        /////////


            // Get the base address of the current module
            hModule = GetModuleHandle(NULL);
            if (hModule == NULL) 
            {
                // Error handling
                return 1;
            }

            // Get the address of the IMAGE_DOS_HEADER
            pDosHeader = (PIMAGE_DOS_HEADER)hModule;

            // Get the address of the IMAGE_NT_HEADERS
            pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pDosHeader->e_lfanew);

            // Get the address of the IMAGE_IMPORT_DESCRIPTOR
            pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

            // Iterate over each imported module
            while (pImportDesc->Name != NULL)
            {
                // Get the name of the imported module
                LPCSTR szModuleName = (LPCSTR)((DWORD_PTR)hModule + pImportDesc->Name);

                // Check if the imported module is kernel32.dll (just as an example)
                if (strcmp(szModuleName, "ws2_32.dll") == 0)
                {
                    // Get the address of the thunk array
                    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModule + pImportDesc->FirstThunk);

                    // Iterate over each function in the import address table (IAT)
                    while (pThunk->u1.Function != NULL)
                    {

                        //send replace
                        if ((DWORD_PTR)pThunk->u1.Function == (DWORD_PTR)originalsend)
                        {
                            // Modify the memory protection of the page
                            DWORD dwOldProtect;
                            if (!VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect))
                            {
                                // Error handling
                                return 1;
                            }

                            // Hook the function by replacing its address with the address of our hooked function
                            pThunk->u1.Function = (DWORD_PTR)hookedsend;

                            // Restore the original memory protection
                            VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);

                            // Move to the next thunk
                            ++pThunk;
                        }
                    }
                }
                if (strcmp(szModuleName, "wsock32.dll") == 0)
                {
                    // Get the address of the thunk array
                    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModule + pImportDesc->FirstThunk);

                    // Iterate over each function in the import address table (IAT)
                    while (pThunk->u1.Function != NULL)
                    {

                        //recv replace
                        if ((DWORD_PTR)pThunk->u1.Function == (DWORD_PTR)originalrecv)
                        {
                            // Modify the memory protection of the page
                            DWORD dwOldProtect;
                            if (!VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect))
                            {
                                // Error handling
                                return 1;
                            }

                            // Hook the function by replacing its address with the address of our hooked function
                            pThunk->u1.Function = (DWORD_PTR)hookedrecv;

                            // Restore the original memory protection
                            VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);

                            // Move to the next thunk
                            ++pThunk;
                        }
                    }
                }
                    // Move to the next imported module
                    ++pImportDesc;
            }
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}
