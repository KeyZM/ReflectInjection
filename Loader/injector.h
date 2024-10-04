#pragma once

#include <Windows.h>

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
