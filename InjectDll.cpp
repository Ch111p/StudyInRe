#include <windows.h>
#include <tchar.h>
#include <stdio.h>

typedef struct UnicodeString {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} unicodeString;
typedef unicodeString *punicodeString;

typedef NTSTATUS(WINAPI *fLdrLoadDll) (
	IN PWCHAR pathToFile OPTIONAL,
	IN ULONG Flags OPTIONAL,
	IN punicodeString moduleFileName,
	OUT HANDLE moduleHandle
	);

typedef VOID(WINAPI *fRtlInitUnicodeString)(
	punicodeString destinationString,
	PCWSTR sourceString	
	);

typedef DWORD64(WINAPI *_NtCreateThreadEx64)(PHANDLE ThreadHandle,
	ACCESS_MASK DesiredAccess,
	LPVOID ObjectAttributes,
	HANDLE ProcessHandle,
	LPTHREAD_START_ROUTINE lpStartAddress,
	LPVOID lpParameter,
	BOOL CreateSuspended,
	DWORD64 dwStackSize,
	DWORD64 dw1,
	DWORD64 dw2,
	LPVOID Unknown
	);

typedef struct threadData {
	fRtlInitUnicodeString fnRtlInitUnicodeString;
	fLdrLoadDll fnLdrLoadDLL;
	HANDLE mouduleHandle;
	unicodeString UnicodeString;
	WCHAR dllName[100];
	ULONG dllFlag;
	PWCHAR dllPath;
}threadData, *pThreadData;

HANDLE WINAPI threadProc(pThreadData data) {
	data -> fnRtlInitUnicodeString(&data -> UnicodeString, data -> dllName);
	data -> fnLdrLoadDLL(data -> dllPath, data -> dllFlag, &data -> UnicodeString, &(data -> mouduleHandle));
	return data -> mouduleHandle;
}

int WINAPI threadProcEnd() {
	return 0;
}

BOOL injectDll(LPCTSTR, DWORD);

int main() {
	WCHAR dllPath[100];
	int dwPid;
	printf("Please input the dwPid and the dll's path which you want to inject:");
	wscanf_s(L"%ls", dllPath, 100);
	scanf_s("%d", &dwPid);
	if (injectDll(LPCTSTR(dllPath), DWORD(dwPid)) == FALSE) {
		_tprintf(L"Inject %ls failed!", dllPath);
	}
	else {
		printf("success!");
	}
	system("pause");
	return 0;
}

BOOL injectDll(LPCTSTR dllPath,DWORD dwPid){
	DWORD dwBufsize = sizeof(threadData);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwPid);
	if (hProcess == NULL) {
		_tprintf(L"OpenProcess error!code:%d", GetLastError());
		return FALSE;
	}
	threadData data;
	HMODULE pNtdll = GetModuleHandleA("ntdll.dll");
	memcpy(data.dllName, dllPath, (wcslen(dllPath) + 1) * sizeof(WCHAR));
	data.fnLdrLoadDLL = (fLdrLoadDll)GetProcAddress(pNtdll, "LdrLoadDll");
	data.fnRtlInitUnicodeString = (fRtlInitUnicodeString)GetProcAddress(pNtdll, "RtlInitUnicodeString");
	data.dllFlag = 0; 
	data.dllPath = NULL;
	data.mouduleHandle = INVALID_HANDLE_VALUE;
	LPVOID pThreadData = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
	BOOL bWriteOK = WriteProcessMemory(hProcess, pThreadData, &data, dwBufsize, NULL);
	if (!bWriteOK) {
		_tprintf(L"WriteProcessMemory ERROR!!");
		return FALSE;
	}
	HANDLE hThread = NULL;
	DWORD sizeOfCode = DWORD(threadProcEnd) - DWORD(threadProc);
	LPVOID pCode = VirtualAllocEx(hProcess, NULL, sizeOfCode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	bWriteOK = WriteProcessMemory(hProcess, pCode, (PVOID)threadProc, sizeOfCode, NULL);
	if (!bWriteOK) {
		_tprintf(L"WriteProcessMemory ERROR!!");
		return FALSE;
	}
	_NtCreateThreadEx64 pFunc = (_NtCreateThreadEx64)GetProcAddress(pNtdll, "NtCreateThreadEx");
	pFunc(&hThread, 0x1FFFFF, NULL, hProcess, (LPTHREAD_START_ROUTINE)pCode, pThreadData, FALSE, NULL, NULL, NULL, NULL);
	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
		printf("%d", GetLastError());
	}
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}