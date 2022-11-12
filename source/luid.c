#include "luid.h"

void execute_luid(WCHAR** dispatch, HANDLE hToken) {
    LUID* currentLUID = GetCurrentLUID(hToken);
    if (currentLUID == NULL) {
        PRINT(dispatch, "[!] Unable to get current session LUID: %ld\n", KERNEL32$GetLastError());
        return;
    }
    PRINT(dispatch, "[+] Current LogonId: %lx:0x%lx\n\n", currentLUID->HighPart, currentLUID->LowPart);
    MSVCRT$free(currentLUID);
}

LUID* GetCurrentLUID(HANDLE TokenHandle) {
    TOKEN_STATISTICS tokenStats;
    DWORD tokenSize;
    if (!ADVAPI32$GetTokenInformation(TokenHandle, TokenStatistics, &tokenStats, sizeof(tokenStats), &tokenSize)) {
        return NULL;
    }

    LUID* luid = MSVCRT$calloc(1, sizeof(LUID));
    if (luid == NULL) {
        return NULL;
    }
    luid->HighPart = tokenStats.AuthenticationId.HighPart;
    luid->LowPart = tokenStats.AuthenticationId.LowPart;
    return luid;
}