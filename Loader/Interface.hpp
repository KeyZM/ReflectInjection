#pragma once

#include "Pch.h"

class Interfaces {

public:

	virtual bool Initialize(DWORD pid) = 0;

	virtual ~Interfaces() = 0 {};


	// ����/�ͷ��ڴ�
	virtual void* MmAlloc(size_t size) = 0;

	virtual bool MmFree(void* addr) = 0;

	virtual bool MmProtect(void* addr, DWORD NewProtect, DWORD64 Size) { return false; };

	// ��/д�ڴ�
	virtual bool MmRead(void* addr, void* buffer, size_t size) = 0;

	virtual bool MmWrite(void* addr, void* data, size_t size) = 0;


	virtual bool CallShellCode(void* pShellCode, void* param) = 0;

};