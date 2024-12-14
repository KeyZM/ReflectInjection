#include "Pch.h"
#include "Injector.h"

int main() {
	HWND hwnd = FindWindowA(NULL, NULL);
	DWORD64 pid = 0;
	GetWindowThreadProcessId(hwnd,(DWORD*)&pid);

	if (pid)
	{
		Interfaces* Memory = new InterfacesR0;
		Memory->Initialize(pid);

		if (ManualMapDll(Memory, L"")) {
			printf("Dll 注入成功\n");
		}
		else {
			printf("Dll 注入失败\n");
		}

		delete Memory;
	}
	return 0;
}

