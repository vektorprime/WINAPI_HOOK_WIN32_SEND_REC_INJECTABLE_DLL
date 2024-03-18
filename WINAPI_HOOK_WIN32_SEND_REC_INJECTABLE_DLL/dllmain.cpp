//working on hooking send and rec

#include "pch.h"
#include <windows.h>
//winsock included in windows
//#include <winsock.h>
#include <winsock2.h>
#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <iomanip> 

#pragma comment(lib, "Ws2_32.lib")
//#pragma comment(lib, "Wsock32.lib")

std::ofstream log_file;


/// Define the prototyps for function pointers
typedef int(WINAPI *Prototypesend)(SOCKET s, const char *buf, int len, int flags);
typedef int(WINAPI *Prototyperecv)(SOCKET s, char *buf, int len, int flags);

////// Pointer to the original functions
//Prototypesend original_send = send;
//Prototyperecv original_recv = recv;


Prototypesend original_send;
Prototyperecv original_recv;

// Hooked send function
int hooked_send(SOCKET s, const char *buf, int len, int flags)
{
    char newbuf1[8];
    bool bypass = false;

    // Open the log file for writing
    log_file.open("dll_log.txt", std::ios::app);
    if (!log_file.is_open()) {
        // Failed to open log file, exit
        return FALSE;
    }
    log_file << "hooked_send triggered" << std::endl;
    log_file << "packet sending is ";


    for (int x = 0; x < len; ++x)
    {
        log_file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(buf[x])) << " ";
    }
    log_file << "\n";
    ////modify the data and send

    bool found_match = false;

    if (len == 8)
    {
        log_file << "Looking at packet with 8 bytes" << std::endl;
        if (buf[4] == static_cast<char>(0xd1)
            && buf[5] == static_cast<char>(0x58)
            && buf[6] == static_cast<char>(0x58)
            && buf[7] == static_cast<char>(0x00))
        {
            log_file << "modifying packet to send skill 3 instead of 0" << std::endl;
            for (int x = 0; x < len; ++x)
            {
                newbuf1[x] = buf[x];
            }
            newbuf1[6] = static_cast<char>(0x01);
            bypass = true;
        }
       // {
            //log_file << "comparing buf[4] with 0xd1" << std::endl;
            //if (buf[4] == static_cast<char>(0xd1))
            //{
            //    log_file << "matched" << std::endl;

            //    log_file << "comparing buf[5] with 0x58" << std::endl;
            //    if (buf[5] == static_cast<char>(0x58))
            //    {
            //        log_file << "matched" << std::endl;

            //        log_file << "comparing buf[6] with 0x18" << std::endl;
            //        if (buf[6] == static_cast<char>(0x18))
            //        {
            //            log_file << "matched" << std::endl;

            //            log_file << "comparing buf[7] with 0x00" << std::endl;
            //            if (buf[7] == static_cast<char>(0x00))
            //            {
            //                log_file << "matched" << std::endl;
            //                found_match = true;
            //            }
            //        }

            //    }
            //  
            //}

            //log_file << "checking found_match" << std::endl;

           // if (found_match == true)
            //{
 
           // }
    
       // }

    }
    log_file.close();
    if (bypass == true)
    {
        // Call the original send with modified data
        return original_send(s, newbuf1, len, flags);
    }
    else
    {
        // Call the original send with unmodified data
        return original_send(s, buf, len, flags);
    }

}

// Hooked send function
int hooked_recv(SOCKET s, char *buf, int len, int flags)
{
    // Open the log file for writing
    log_file.open("dll_log.txt", std::ios::app);
    if (!log_file.is_open()) {
        // Failed to open log file, exit
        return FALSE;
    }
    log_file << "hooked_recv triggered" << std::endl;
    log_file << "packet received is ";


    for (int x = 0; x < len; ++x)
    {
        log_file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(buf[x])) << " ";

    }
    log_file << "\n";
  
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
   // MessageBoxW(NULL, L"HIT RECV", L"HIT RECV", 0);
    // Call the original send with the modified data
    log_file.close();
    return original_recv(s, buf, len, flags);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{


    ///logging
    // Open the log file for writing
    log_file.open("dll_log.txt", std::ios::app);
    if (!log_file.is_open()) {
        // Failed to open log file, exit
        return FALSE;
    }

    log_file << "log started\n";

    ///other
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
   

             // Output initialization message to log file
             log_file << "attached\n";

             /////////        /////////        /////////        /////////
             // Get the address of the send function
             original_send = (Prototypesend)GetProcAddress(GetModuleHandle(L"ws2_32.dll"), "send");
             //original_send = (Prototypesend)GetProcAddress(GetModuleHandle(L"wsock32.dll"), "send");
             log_file << "original_send func address is " << original_send << std::endl;

             if (original_send == NULL)
             {
                 // Error handling
                 return FALSE;
             }

             // Get the address of the recv function
             original_recv = (Prototyperecv)GetProcAddress(GetModuleHandle(L"wsock32.dll"), "recv");
             log_file << "original_recv func address is " << original_recv << std::endl;

             if (original_recv == NULL)
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
            log_file << "pDosHeader address is " << pDosHeader << std::endl;

            // Get the address of the IMAGE_NT_HEADERS
            pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)hModule + pDosHeader->e_lfanew);
            log_file << "pNtHeader address is " << pNtHeader << std::endl;

            // Get the address of the IMAGE_IMPORT_DESCRIPTOR
            pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)hModule + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            log_file << "pImportDesc address is " << pImportDesc << std::endl;

            // Iterate over each imported module
            while (pImportDesc->Name != NULL)
            {
                log_file << "Iterating over pImportDesc" << std::endl;

                // Get the name of the imported module
              //  LPCWSTR szModuleName = reinterpret_cast<LPCWSTR>((DWORD_PTR)hModule + pImportDesc->Name);
                LPCSTR szModuleName = reinterpret_cast<LPCSTR>((DWORD_PTR)hModule + pImportDesc->Name);
                log_file << "szModuleName is " << szModuleName << std::endl;
                // Check if the imported module is kernel32.dll (just as an example)
                std::string module_name_lower(szModuleName);
                std::transform(module_name_lower.begin(), module_name_lower.end(), module_name_lower.begin(), ::tolower);
                if (module_name_lower == "ws2_32.dll")
                {
                    log_file << "Found ws2_32.dll" << std::endl;
                    // Get the address of the thunk array
                    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModule + pImportDesc->FirstThunk);
                    log_file << "ws2_32 pThunk array address is " << pThunk << std::endl;
                    log_file << "original_send func address is " << original_send << std::endl;
                    // Iterate over each function in the import address table (IAT)
                    bool send_found = false;
                    while (send_found == false)
                    {
                        log_file << "pThunk->u1.Function address: " << (DWORD_PTR)pThunk->u1.Function << std::endl;
                        //send replace
                        if ((DWORD_PTR)pThunk->u1.Function == (DWORD_PTR)original_send)
                        {
                            send_found = true;
                            log_file << "Found original_send in the thunk array" << std::endl;
                            // Modify the memory protection of the page
                            DWORD dwOldProtect;
                            if (!VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect))
                            {
                                // Error handling
                                return 1;
                            }
                            log_file << "Set the memory area of the IAT to PAGE_READWRITE" << std::endl;

                            // Hook the function by replacing its address with the address of our hooked function
                            pThunk->u1.Function = (DWORD_PTR)hooked_send;
                            log_file << "Wrote the hooked_recv in the IAT" << std::endl;

                            // Restore the original memory protection
                            VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);
                            log_file << "Set the memory area of the IAT back to protected" << std::endl;

                            // Move to the next thunk
                        }
                        ++pThunk;

                    }
                }
                if (module_name_lower == "wsock32.dll")
                {
                    log_file << "Found wsock32.dll" << std::endl;
                    // Get the address of the thunk array
                    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)hModule + pImportDesc->FirstThunk);
                    log_file << "wsock32 pThunk array address is " << pThunk << std::endl;
                    log_file << "original_recv func address is " << original_recv << std::endl;
                    // Iterate over each function in the import address table (IAT)
                    bool recv_found = false;
                    while (recv_found == false)
                    {
                        log_file << "pThunk->u1.Function address: " << (DWORD_PTR)pThunk->u1.Function << std::endl;

                        //recv replace
                        if ((DWORD_PTR)pThunk->u1.Function == (DWORD_PTR)original_recv)
                        {
                            recv_found = true;
                            log_file << "Found original_recv in the thunk array" << std::endl;

                            // Modify the memory protection of the page
                            DWORD dwOldProtect;
                            if (!VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), PAGE_READWRITE, &dwOldProtect))
                            {
                                // Error handling
                                return 1;
                            }
                            log_file << "Set the memory area of the IAT to PAGE_READWRITE" << std::endl;

                            // Hook the function by replacing its address with the address of our hooked function
                            pThunk->u1.Function = (DWORD_PTR)hooked_recv;

                            log_file << "Wrote the hooked_recv in the IAT" << std::endl;

                            // Restore the original memory protection
                            VirtualProtect(&pThunk->u1.Function, sizeof(DWORD_PTR), dwOldProtect, &dwOldProtect);

                            log_file << "Set the memory area of the IAT back to protected" << std::endl;
                        }
                        // Move to the next thunk
                        ++pThunk;
                    }
                }
                    // Move to the next imported module
                    ++pImportDesc;
            }

            log_file << "ALL HOOKS SET!" << std::endl;

            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            // Close the log file
            log_file.close();
            break;
    }

    return TRUE;
}
