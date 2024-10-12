#include "pch.h"

int main() {
	HWND hwnd = FindWindowA(NULL, NULL);
	DWORD64 pid;

	GetWindowThreadProcessId(hwnd, (DWORD*)&pid);

	if (pid)
	{
		//inject
	}
	return 0;
}	