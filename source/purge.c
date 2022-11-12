#include "purge.h"

void execute_purge(WCHAR** dispatch, HANDLE hToken, LUID luid, BOOL currentLuid) {
    ULONG authPackage;
    HANDLE hLsa;
    void* purgeResponse;
    ULONG responseSize;
    NTSTATUS protocolStatus;

    BOOL highIntegrity = IsHighIntegrity(hToken);
    if (!highIntegrity && !currentLuid) {
        PRINT(dispatch, "[!] Not in high integrity.\n");
        return;
    }

    if (currentLuid) {
        highIntegrity = FALSE;
    }

    NTSTATUS status = GetLsaHandle(hToken, highIntegrity, &hLsa);
    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] GetLsaHandle %ld\n", status);
        return;
    }
    LSA_STRING krbAuth = {.Buffer = "kerberos", .Length = 8, .MaximumLength = 9};
    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage);
    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] LsaLookupAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    KERB_PURGE_TKT_CACHE_REQUEST purgeRequest;
    purgeRequest.MessageType = KerbPurgeTicketCacheMessage;
    if (highIntegrity) {
        purgeRequest.LogonId = luid;
    } else {
        purgeRequest.LogonId = (LUID){.HighPart = 0, .LowPart = 0};
    }
    purgeRequest.RealmName = (UNICODE_STRING){.Buffer = L"", .Length = 0, .MaximumLength = 1};
    purgeRequest.ServerName = (UNICODE_STRING){.Buffer = L"", .Length = 0, .MaximumLength = 1};
    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &purgeRequest, 
        sizeof(KERB_PURGE_TKT_CACHE_REQUEST), &purgeResponse, &responseSize, &protocolStatus);

    if (NT_SUCCESS(status)) {
        if (NT_SUCCESS(protocolStatus)) {
            PRINT(dispatch, "[+] Successfully purged tickets.\n");
        } else {
            PRINT(dispatch, "[!] LsaCallAuthenticationPackage ProtocolStatus %ld\n",
                  ADVAPI32$LsaNtStatusToWinError(protocolStatus));
        }
    } else {
        PRINT(dispatch, "[!] LsaCallAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
    }

    SECUR32$LsaDeregisterLogonProcess(hLsa);
}