// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <Windows.h>
#include <iostream>
#include <string>
#include <winternl.h>

HANDLE hook_CreateFileW(
	           LPCWSTR               lpFileName,
	DWORD                 dwDesiredAccess,
	DWORD                 dwShareMode,
	LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	DWORD                 dwCreationDisposition,
	DWORD                 dwFlagsAndAttributes,
	HANDLE                hTemplateFile
)
{
	std::cout << "Working" << std::endl;
	return NULL;
}

void analyzeImportDescriptor
(
	IMAGE_IMPORT_DESCRIPTOR importDescriptor,
	PIMAGE_NT_HEADERS64 peHeader,
	DWORD64 baseAddress
)
{
	PIMAGE_THUNK_DATA64 thunkILT;
	PIMAGE_THUNK_DATA64 thunkIAT;
	PIMAGE_IMPORT_BY_NAME nameData;


	thunkILT = (PIMAGE_THUNK_DATA64)(importDescriptor.OriginalFirstThunk + baseAddress);
	thunkIAT = (PIMAGE_THUNK_DATA64)(importDescriptor.FirstThunk + baseAddress);
	while (thunkILT->u1.AddressOfData != 0) {
		if (!(thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
			nameData = (PIMAGE_IMPORT_BY_NAME)(thunkILT->u1.AddressOfData + baseAddress);
			std::cout << "-" << nameData->Name << std::endl;
			if (!strcmp("CreateFileW", nameData->Name)) {
				DWORD  oldProtectionFlags;
				VirtualProtect(&thunkIAT->u1.Function, sizeof(DWORD64), PAGE_EXECUTE_READWRITE, &oldProtectionFlags);
				thunkIAT->u1.Function = (DWORD64)hook_CreateFileW;
				std::cout << "Replaced" << std::endl;
				VirtualProtect(&thunkIAT->u1.Function, sizeof(DWORD64), oldProtectionFlags, NULL);
			}
		}

		thunkILT++;
		thunkIAT++;
	}

	return;
}

bool Hook()
{
	AllocConsole();
	FILE* fOut;
	freopen_s(&fOut, "CONOUT$", "w", stdout);
	DWORD64 baseAddr = (DWORD64)GetModuleHandle(NULL);

	PIMAGE_DOS_HEADER dosHeader;
	dosHeader = (PIMAGE_DOS_HEADER)baseAddr;
	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}
	PIMAGE_NT_HEADERS64 peHeader = (PIMAGE_NT_HEADERS64)(baseAddr + dosHeader->e_lfanew);
	if (peHeader->Signature != IMAGE_NT_SIGNATURE) {
		return(FALSE);
	}
	IMAGE_OPTIONAL_HEADER64 optionalHeader;
	optionalHeader = peHeader->OptionalHeader;
	if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return FALSE;
	IMAGE_DATA_DIRECTORY importDirectory;
	importDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	DWORD64 descriptorStartRVA = importDirectory.VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(descriptorStartRVA + baseAddr);

	for (int i = 0; importDescriptor[i].Characteristics != 0; i++)
	{
		DWORD64 dllname = importDescriptor[i].Name + baseAddr;
		std::cout << "DLL name: " << (char*)dllname << std::endl;
		//if (strcmp((char*)dllname, "KERNEL32.dll") != 0)
		//	continue;
		analyzeImportDescriptor(
			importDescriptor[i],
			peHeader,
			baseAddr);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Hook();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
