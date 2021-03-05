#include <iostream>
#include <Windows.h>

void dest() {
	puts("After EIP overwrite");
}

void source(){
	puts("Before EIP overwrite");
}

LONG WINAPI pVeh(EXCEPTION_POINTERS *excPtr) {
	if (memcmp((void *)excPtr->ContextRecord->Eip, source, 4)) {
		std::cout << "[*] Lets patch -> " << excPtr->ContextRecord->Eip << std::endl;
		VirtualProtect((LPVOID)excPtr->ContextRecord->Eip, 4, PAGE_EXECUTE_READWRITE, NULL);
		excPtr->ContextRecord->Eip = (DWORD_PTR)dest;
	}
	excPtr->ContextRecord->ContextFlags |= 0x100;
	return EXCEPTION_CONTINUE_EXECUTION;
}

int main() {
	AddVectoredExceptionHandler(1, pVeh);
	LPVOID addr = VirtualAlloc(NULL, 4, MEM_COMMIT | MEM_RESERVE, PAGE_GUARD | PAGE_READONLY);
	memset(addr, 0x90, 4);
	RemoveVectoredExceptionHandler(pVeh);
	return 0;
}
