#include "Pch.h"
#include "Injector.h"
#include <d3d11.h>

bool FreeMemory(Interfaces* Memory, std::vector<void*> addrs)
{
	for (size_t i = 0; i < addrs.size(); i++){
		void* addr = addrs.at(i);

		if (addr) {
			Memory->MmFree(addr);
		}
	}

	return false;
}

BYTE ShellByte[]
{
	0x48,0x83,0xEC,0x28,
	0x48,0xB8,00,00,00,00,00,00,00,00,
	0x48,0xA3,00,00,00,00,00,00,00,00,
	0x48,0xB9,00,00,00,00,00,00,00,00,
	0x48,0xB8,00,00,00,00,00,00,00,00,
	0xFF,0xD0,
	0x33,0xC0,
	0x48,0x83,0xC4,0x28,
	0xC3
};

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
bool ManualMapDll(Interfaces* Memory, const wchar_t* DllPath)
{
	size_t FileSize;
	BYTE* pSrcData = nullptr;
	void* pShellCode = nullptr;
	BYTE* pTargetBase = nullptr;
	IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
	IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
	IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;

	//读入文件以及获取文件大小
	std::ifstream File(DllPath,std::ios::binary | std::ios::ate);
	FileSize = File.tellg();
	pSrcData = new BYTE[(UINT_PTR)FileSize];

	File.seekg(0, std::ios::beg);
	File.read((char*)(pSrcData), FileSize);
	File.close();

	//获取PE/扩展头
	pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
	pOldFileHeader = &pOldNtHeader->FileHeader;
	pOldOptHeader = &pOldNtHeader->OptionalHeader;

	//判断是否为PE文件,以及判断运行平台是否支持
	if (reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_magic != IMAGE_DOS_SIGNATURE
		|| pOldFileHeader->Machine != CURRENT_ARCH)
	{ 
		delete[] pSrcData;
		return false;
	}


	pShellCode = Memory->MmAlloc(0x1000);//修复函数地址
	pTargetBase = reinterpret_cast<BYTE*>(Memory->MmAlloc(pOldOptHeader->SizeOfImage));//dll加载地址
	BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(Memory->MmAlloc(sizeof(MANUAL_MAPPING_DATA)));//修复函数参数地址

	if (!pShellCode || !pTargetBase || !MappingDataAlloc) {
		delete[] pSrcData;
		return FreeMemory(Memory,{ pShellCode,pTargetBase,MappingDataAlloc });
	}

	//写入内存展开DLL
	Memory->MmWrite(pTargetBase, pSrcData, pOldOptHeader->SizeOfHeaders);
	IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
	for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
		if (pSectionHeader->SizeOfRawData) {
			Memory->MmWrite(pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
		}
	}

	//写入修复函数以及参数
	MANUAL_MAPPING_DATA data{ 0 };
	data.pbase = pTargetBase;
	data.pLoadLibraryA = LoadLibraryA;
	data.pGetProcAddress = GetProcAddress;
	Memory->MmWrite(pShellCode, Shellcode, 0x1000);
	Memory->MmWrite(MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA));

	IDXGISwapChain* pSwapChain = NULL;
	DXGI_SWAP_CHAIN_DESC sd;
	ZeroMemory(&sd, sizeof(sd));
	sd.BufferCount = 2;
	sd.BufferDesc.Width = 0;
	sd.BufferDesc.Height = 0;
	sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	sd.BufferDesc.RefreshRate.Numerator = 60;
	sd.BufferDesc.RefreshRate.Denominator = 1;
	sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
	sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	sd.OutputWindow = GetForegroundWindow();
	sd.SampleDesc.Count = 1;
	sd.SampleDesc.Quality = 0;
	sd.Windowed = TRUE;
	sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

	UINT createDeviceFlags = 0;
	D3D_FEATURE_LEVEL featureLevel;
	const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0, };
	if (D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &pSwapChain, NULL, &featureLevel, NULL) != S_OK)
		return false;

	//组装/写入ShellCode
	DWORD64* SwapVTable = (*(DWORD64**)pSwapChain);
	void* pShellByte = (BYTE*)pShellCode + 0x1000 - sizeof(ShellByte);
	*(DWORD64*)(ShellByte + 6) = SwapVTable[8];
	*(DWORD64*)(ShellByte + 16) = (DWORD64)(SwapVTable + 8);
	*(DWORD64*)(ShellByte + 26) = (DWORD64)MappingDataAlloc;
	*(DWORD64*)(ShellByte + 36) = (DWORD64)pShellCode;
	Memory->MmWrite(pShellByte, ShellByte, sizeof(ShellByte));

	//给头文件写入虚表,可以用这种办法来传递参数
	Memory->MmWrite(pTargetBase, &SwapVTable, sizeof(void*));

	//更改虚表
	Memory->MmProtect(SwapVTable,PAGE_READWRITE,0x100);
	Memory->MmWrite(SwapVTable + 8, &pShellByte, 8);

	//判断ShellCode是否被调用
	while (1)
	{
		MANUAL_MAPPING_DATA data;
		Memory->MmRead(MappingDataAlloc,&data,sizeof(MANUAL_MAPPING_DATA));

		if (data.hMod == (HINSTANCE)0x404040) {
			delete[] pSrcData;
			return FreeMemory(Memory, { pShellCode,pTargetBase,MappingDataAlloc });
		}

		if (data.hMod != 0)
		{
			break;
		}
		
	}

	//还原虚表保护属性
	Memory->MmProtect(SwapVTable,PAGE_EXECUTE_READ, 0x100);

	//清理PE头
	void* buffer = malloc(pOldOptHeader->SizeOfHeaders);
	RtlZeroMemory(buffer, pOldOptHeader->SizeOfHeaders);
	Memory->MmWrite(pTargetBase, buffer, pOldOptHeader->SizeOfHeaders);
	free(buffer);

	//释放内存
	delete[] pSrcData;
	pSwapChain->Release();
	FreeMemory(Memory, { pShellCode,MappingDataAlloc });
	return true;
}


void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData) {
	if (!pData) {
		pData->hMod = (HINSTANCE)0x404040;
		return;
	}

	BYTE* pBase = pData->pbase;
	auto* pOpt = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>((uintptr_t)pBase)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<fn_DLL_ENTRY_POINT>(pBase + pOpt->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOpt->ImageBase;
	if (LocationDelta) {
		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
			auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
			while (pRelocData->VirtualAddress) {
				UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
				WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

				for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
					if (RELOC_FLAG(*pRelativeInfo)) {
						UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
						*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
					}
				}
				pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
			}
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name) {
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else {
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}
