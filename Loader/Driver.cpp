#include "Pch.h"
#include "Driver.h"

Driver GDriver;

bool Driver::Initialize(DWORD pid)
{
	this->pid = pid;
	handle = CreateFileA("\\\\.\\62A5E490880A92EEF74F167D9DC6DCA0", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	return handle ? true : false;
}

Driver::~Driver()
{
	if (handle)
		CloseHandle(handle);
}

void* Driver::MmAlloc(size_t size)
{
	MmAllocData Data;
	RtlZeroMemory(&Data, sizeof(Data));
	Data.Pid = pid;
	Data.Type = MEM_COMMIT | MEM_RESERVE;
	Data.Protect = PAGE_EXECUTE_READWRITE;
	Data.Size = size;

	DWORD RetSize = 0;
	DeviceIoControl(handle, ALLOC, &Data, sizeof(Data), &Data, sizeof(Data), &RetSize, 0);

	return RetSize ? Data.Address : NULL;
}

bool Driver::MmFree(void* addr)
{
	MmAllocData Data;
	RtlZeroMemory(&Data, sizeof(Data));
	Data.Pid = pid;
	Data.Address = (DWORD64*)addr;
	Data.Type = MEM_RELEASE;

	DWORD RetSize = 0;
	DeviceIoControl(handle, FREE, &Data, sizeof(Data), 0, 0, &RetSize, 0);

	return RetSize ? true : false;
}

bool Driver::MmProtect(void* addr, DWORD NewProtect, DWORD64 Size)
{
	MmAllocData Data;
	RtlZeroMemory(&Data, sizeof(Data));
	Data.Pid = pid;
	Data.Address = (DWORD64*)addr;
	Data.Protect = NewProtect;
	Data.Size = Size;

	DWORD RetSize = 0;
	DeviceIoControl(handle, PROTECT, &Data, sizeof(Data), 0, 0, &RetSize, 0);

	return RetSize ? true : false;
}

bool Driver::MmRead(void* addr, void* buffer, size_t size)
{
	MmData Data;
	RtlZeroMemory(&Data, size);
	Data.Pid = pid;
	Data.Address = addr;
	Data.Buffer = buffer;
	Data.Size = size;

	DWORD RetSize = 0;
	DeviceIoControl(handle, READ, &Data, size,0, 0, &RetSize, 0);

	return RetSize ? true : false;
}

bool Driver::MmWrite(void* addr, void* data, size_t size)
{
	MmData Data;
	RtlZeroMemory(&Data, sizeof(Data));
	Data.Pid = pid;
	Data.Address = addr;
	Data.Buffer = data;
	Data.Size = size;

	DWORD RetSize = 0;
	DeviceIoControl(handle, WRITE, &Data, sizeof(Data), 0, 0, &RetSize, 0);

	return RetSize ? true : false;
}

bool Driver::CallShellCode(void* pShellCode, void* param)
{
	InjectorData Data;
	RtlZeroMemory(&Data, sizeof(Data));
	Data.Pid = pid;
	Data.CallAddress = (DWORD64*)pShellCode;
	Data.Params = (DWORD64*)param;

	DWORD RetSize = 0;
	DeviceIoControl(handle, CALL, &Data, sizeof(Data), 0, 0, &RetSize, 0);

	return RetSize ? true : false;
}