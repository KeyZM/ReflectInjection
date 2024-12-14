#pragma once

#include "Pch.h"
#include "Driver.h"

class Interfaces {

public:

	virtual bool Initialize(DWORD pid) = 0;

	virtual ~Interfaces() = 0 {};


	// 开辟/释放内存
	virtual void* MmAlloc(size_t size) = 0;

	virtual bool MmFree(void* addr) = 0;

	virtual bool MmProtect(void* addr, DWORD NewProtect, DWORD64 Size) { return false; };

	// 读/写内存
	virtual bool MmRead(void* addr, void* buffer, size_t size) = 0;

	virtual bool MmWrite(void* addr, void* data, size_t size) = 0;


	virtual bool CallShellCode(void* pShellCode,void* param) = 0;

};

class InterfacesR3 : public Interfaces {

public:

	bool Initialize(DWORD pid){
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
		return hProcess ? true : false;
	}

	~InterfacesR3() {
		if (hProcess)
			CloseHandle(hProcess);
	}


	void* MmAlloc(size_t size) {
		return VirtualAllocEx(this->hProcess, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	}

	bool MmFree(void* addr) {
		return VirtualFreeEx(this->hProcess, reinterpret_cast<void*>(addr), 0, MEM_RELEASE);
	}


	bool MmRead(void* addr, void* buffer, size_t size) {
		return ReadProcessMemory(this->hProcess, addr, buffer, size, nullptr);
	}

	bool MmWrite(void* addr, void* data, size_t size) {
		return WriteProcessMemory(this->hProcess, addr, data, size, nullptr);
	}


	bool CallShellCode(void* pShellCode, void* param) {
		HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellCode), param, 0, nullptr);
		return hThread ? CloseHandle(hThread) : false;
	}

private:

	HANDLE hProcess = nullptr;

};

class InterfacesR0 : public Interfaces {

public:

	bool Initialize(DWORD pid) {
		return GDriver.Initialize(pid);
	}

	~InterfacesR0() {
		GDriver.~Driver();
	}


	void* MmAlloc(size_t size) {
		return GDriver.MmAlloc(size);
	}

	bool MmFree(void* addr) {
		return GDriver.MmFree(addr);
	}

	bool MmProtect(void* addr, DWORD NewProtect, DWORD64 Size) {
		return GDriver.MmProtect(addr, NewProtect, Size);
	}

	bool MmRead(void* addr, void* buffer, size_t size) {
		return GDriver.MmRead(addr, buffer, size);
	}

	bool MmWrite(void* addr, void* data, size_t size) {
		return GDriver.MmWrite(addr, data, size);
	}


	bool CallShellCode(void* pShellCode, void* param) {
		return GDriver.CallShellCode(pShellCode, param);
	}
};