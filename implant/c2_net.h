#ifndef C2_NET
#define C2_NET

#include <winsock2.h>
#include <stdarg.h>
#include <stdio.h>

// Libraries
#pragma comment(lib, "ws2_32.lib")

// Function to set up communication (initialize Winsock)
BOOL setup_comms();

// Function to establish a TCP connection to a remote host
SOCKET c2_connect(char* ip, unsigned short port);

// Function to send data over a socket
int c2_send(SOCKET s, char* data, int len);

// Function to receive data from a socket
int c2_recv(SOCKET s, char* buffer, int len);

// Variadic logging function similar to printf.
// Only prints stuff if the DEBUG flag is set.
// Otherwise, it is compiled to do nothing.
void c2_log(const char* format, ...);

#endif