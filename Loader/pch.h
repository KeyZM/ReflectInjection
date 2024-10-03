#pragma once

#include <vector>
#include <fstream>
#include <iostream>
#include <Windows.h>

int main() {
	HWND hwnd = FindWindowA(NULL, NULL);
	DWORD64 pid;

	GetWindowThreadProcessId(hwnd, (DWORD*)&pid);

	if (pid)
	{

	}
	return;
}