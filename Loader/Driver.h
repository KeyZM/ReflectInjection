#ifndef DRIVER_H
#define DRIVER_H

#include "Pch.h"

#define CALL	CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define READ	CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define WRITE	CTL_CODE(FILE_DEVICE_UNKNOWN,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define ALLOC	CTL_CODE(FILE_DEVICE_UNKNOWN,0x803,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define FREE	CTL_CODE(FILE_DEVICE_UNKNOWN,0x804,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define PROTECT CTL_CODE(FILE_DEVICE_UNKNOWN,0x806,METHOD_BUFFERED,FILE_ANY_ACCESS)

typedef struct _InjectorData
{
	DWORD64 Pid;
	DWORD64* CallAddress;
	DWORD64* Params;

}InjectorData, * pInjectorData;

typedef struct _MmAllocData
{
	DWORD64 Pid;
	DWORD64 Size;
	DWORD64* Address;
	DWORD Type;
	DWORD Protect;
}MmAllocData,*pMmAllocData;

typedef struct _MmData
{
	DWORD64 Pid;
	DWORD64 Size;
	VOID* Buffer;
	VOID* Address;
}MmData,*pMmData;

class Driver
{
public:
	bool Initialize(DWORD pid);

	~Driver();


	// 开辟/释放内存
	void* MmAlloc(size_t size);

	bool MmFree(void* addr);

	bool MmProtect(void* addr, DWORD NewProtect, DWORD64 Size);

	// 读/写内存
	bool MmRead(void* addr, void* buffer, size_t size);

	bool MmWrite(void* addr, void* data, size_t size);


	bool CallShellCode(void* pShellCode, void* param);

private:

	DWORD pid = 0;
	HANDLE handle = 0;
};

extern Driver GDriver;

#endif // !DRIVER_H
