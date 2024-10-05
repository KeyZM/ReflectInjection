#pragma once

#include <Windows.h>
#include "Interface.hpp"

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define RELOC_FLAG RELOC_FLAG32
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif

using fn_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using fn_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using fn_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

struct MANUAL_MAPPING_DATA
{
	BYTE* pbase;
	HINSTANCE hMod;
	fn_LoadLibraryA pLoadLibraryA;
	fn_GetProcAddress pGetProcAddress;
};