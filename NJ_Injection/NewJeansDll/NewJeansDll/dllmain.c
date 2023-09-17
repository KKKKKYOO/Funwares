#include <Windows.h>
#include <stdio.h>

VOID OpenNewJeansVideo() {
    LPCSTR url = "https://www.youtube.com/watch?v=jOTfBlKSQYY";
    LPCSTR chromePath = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

    char command[512];
    sprintf_s(command, sizeof(command), "\"%s\" \"%s\"", chromePath, url);


    HINSTANCE hRet = ShellExecute(NULL, "open", NULL, command, NULL, SW_SHOWNORMAL);
    if ((int)hRet <= 32) {
        printf("[!] Failed to open URL. Error: %d\n", (int)hRet);
    }
}

DWORD WINAPI ThreadProc(LPVOID lpParameter) {
    OpenNewJeansVideo();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, 0, ThreadProc, NULL, 0, NULL);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
