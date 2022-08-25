 // dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <iostream>


using PrototypeSleep = void (__stdcall*)(DWORD milliseconds);
PrototypeSleep originalSleep = Sleep;

void __stdcall hookedSleep(DWORD milliseconds) {
    printf("[HOOKED!] --> %d\n", milliseconds);
    return originalSleep(50);
}



uintptr_t GetBaseAddress(DWORD procId, wchar_t* modName) { // need to troubleshoot this further


    uintptr_t modBase = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
    if (hSnap && hSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnap, &modEntry)) {
            do {
                if (!_wcsicmp(modEntry.szModule, modName)) {
                    modBase = (uintptr_t)modEntry.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
        CloseHandle(hSnap);
        return modBase;
    }
    else {
        return NULL;
    }
  
    
}



void processImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR importDescriptor, PIMAGE_NT_HEADERS nt, uintptr_t base, char* apiName) {




    PIMAGE_THUNK_DATA thunkILT = (PIMAGE_THUNK_DATA)(importDescriptor->OriginalFirstThunk + base);
    PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)(importDescriptor->FirstThunk + base);
    int nFunctions;
    int nOrdinalFunctions;
    

    if (thunkILT == NULL) {
        printf("[ILT EMPTY]\n");
        return;
    }
    if (thunkIAT == NULL) {
        printf("[IAT EMPTY]\n");
        return;
    }


    nFunctions = 0;
    nOrdinalFunctions = 0;
    while (thunkILT->u1.AddressOfData != 0) {
        if (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
            printf("[PROCESS IMPORT DESCRIPTOR]\t--->\t");

            PIMAGE_IMPORT_BY_NAME nameArray;
            uintptr_t funcNameAddress;

            nameArray = (PIMAGE_IMPORT_BY_NAME)(thunkILT->u1.AddressOfData);
            funcNameAddress = base + (uintptr_t)(nameArray->Name);

            printf("%s\n", (char*)funcNameAddress);
            if (!_stricmp(apiName, (char*)funcNameAddress)) {
                printf("\n\n[MATCH FOUND]\n\n");
                DWORD oldProtect = 0;
                VirtualProtect((LPVOID)(&thunkIAT->u1.Function), 8, PAGE_READWRITE, &oldProtect);
                thunkIAT->u1.Function = (DWORD)hookedSleep;
                printf("[FUNCTION HOOKED]\n");
            }


        }
        else {
            nOrdinalFunctions++;
        }
        thunkILT++;
        thunkIAT++;
        nFunctions++;
    }

    printf("[%d func (%d ordinal)]\n", nFunctions, nOrdinalFunctions);
    return;

}





DWORD WINAPI main(HMODULE hModule) {
    

    bool check1 = true;
    bool check2 = true;

    printf("[DLL MAIN]: successfully loaded into PID(%d)\n", GetCurrentProcessId());

   // printf("here");
    wchar_t* procName = (wchar_t*)L"Victim.exe";
    uintptr_t base = GetBaseAddress(GetCurrentProcessId(), procName);
    printf("BASE: %x\n", base);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);

    PIMAGE_OPTIONAL_HEADER opt = (PIMAGE_OPTIONAL_HEADER)&nt->OptionalHeader;
    PIMAGE_DATA_DIRECTORY importDir = &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    uintptr_t descriptorRVA = importDir->VirtualAddress;
    printf("\n\n descriptor RVA -> %x\n\n", descriptorRVA);
    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(base + descriptorRVA);
    

    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        printf("Could not resolve DOS header. Found: %x\n", dos->e_magic);
        check1 = false;
    }
    
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        printf("Could not resolve PE header. Found: %x\n", nt->Signature);
        check2 = false;
    }
    

    if (check1 && check2) {
        int i = 0;
        while (importDescriptor[i].Characteristics != 0) {
            char* dllName = (char*)(importDescriptor[i].Name + base);
            printf("%s\n", dllName);
            processImportDescriptor(&importDescriptor[i], nt, base, (char*)"Sleep");
            i++;
        }



        while (true) {
            if (GetAsyncKeyState(VK_END) & 1) {
                break;
            }

        }
    }
    
    


   
    printf("[EJECTING DLL]\n");
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}











BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)main, hModule, 0, nullptr));
    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

