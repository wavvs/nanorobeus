#include "luid.h"

void execute_luid(WCHAR **dispatch)
{
    LUID *currentLUID = GetCurrentLUID();
    if (currentLUID == NULL)
    {
        PRINT(dispatch, "[!] Unable to get current session LUID: %ld\n", KERNEL32$GetLastError());
        return;
    }
    PRINT(dispatch, "[+] Current LogonId: %lx:0x%lx\n\n", currentLUID->HighPart, currentLUID->LowPart);
    MSVCRT$free(currentLUID);
}

LUID *GetCurrentLUID()
{
    TOKEN_STATISTICS tokenStats;
    DWORD tokenSize;
    HANDLE hToken = GetCurrentToken(0x8); // TOKEN_QUERY
    if (hToken != NULL)
    {
        if (ADVAPI32$GetTokenInformation(hToken, TokenStatistics, &tokenStats, sizeof(tokenStats), &tokenSize))
        {
            KERNEL32$CloseHandle(hToken);
        }
        else
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }

    LUID *luid = MSVCRT$calloc(1, sizeof(LUID));
    if (luid == NULL)
    {
        return NULL;
    }
    luid->HighPart = tokenStats.AuthenticationId.HighPart;
    luid->LowPart = tokenStats.AuthenticationId.LowPart;
    return luid;
}