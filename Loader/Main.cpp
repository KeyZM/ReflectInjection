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
			printf("Dll ע��ɹ�\n");
		}
		else {
			printf("Dll ע��ʧ��\n");
		}

		delete Memory;
	}
	return 0;
}

