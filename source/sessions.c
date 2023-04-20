#include "sessions.h"

void execute_sessions(WCHAR **dispatch, LUID luid, BOOL currentLuid)
{
    BOOL highIntegrity = IsHighIntegrity();
    if (!highIntegrity && !currentLuid)
    {
        PRINT(dispatch, "[!] Not in high integrity.\n");
        return;
    }

    LOGON_SESSION_DATA sessionData;
    PSECURITY_LOGON_SESSION_DATA data;
    NTSTATUS status = GetLogonSessionData(luid, &sessionData);
    if (NT_SUCCESS(status))
    {
        for (int i = 0; i < sessionData.sessionCount; i++)
        {
            data = sessionData.sessionData[i];
            if (data != NULL)
            {
                char *sessionString;
                PrintLogonSessionData(*data, &sessionString);
                if (sessionString != NULL)
                {
                    PRINT(dispatch, "%s\n\n", sessionString);
                    MSVCRT$free(sessionString);
                }
                else
                {
                    PRINT(dispatch, "[!] Unable to print session.\n\n");
                }
                SECUR32$LsaFreeReturnBuffer(data);
            }
        }
        MSVCRT$free(sessionData.sessionData);
    }
    else
    {
        PRINT(dispatch, "[!] GetLogonSessionData: %ld", status);
    }
}

NTSTATUS GetLogonSessionData(LUID luid, LOGON_SESSION_DATA *data)
{
    LOGON_SESSION_DATA sessionData;
    PSECURITY_LOGON_SESSION_DATA logonData = NULL;
    NTSTATUS status;
    if (luid.LowPart != 0)
    {
        status = SECUR32$LsaGetLogonSessionData(&luid, &logonData);
        if (NT_SUCCESS(status))
        {
            sessionData.sessionData = MSVCRT$calloc(1, sizeof(*sessionData.sessionData));
            if (sessionData.sessionData != NULL)
            {
                sessionData.sessionCount = 1;
                sessionData.sessionData[0] = logonData;
                *data = sessionData;
            }
            else
            {
                status = STATUS_MEMORY_NOT_ALLOCATED;
            }
        }
        else
        {
            status = ADVAPI32$LsaNtStatusToWinError(status);
        }
    }
    else
    {
        ULONG logonSessionCount;
        PLUID logonSessionList;
        status = SECUR32$LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList);
        if (NT_SUCCESS(status))
        {
            sessionData.sessionData = MSVCRT$calloc(logonSessionCount, sizeof(*sessionData.sessionData));
            if (sessionData.sessionData != NULL)
            {
                sessionData.sessionCount = logonSessionCount;
                for (int i = 0; i < logonSessionCount; i++)
                {
                    LUID luid = logonSessionList[i];
                    status = SECUR32$LsaGetLogonSessionData(&luid, &logonData);
                    if (NT_SUCCESS(status))
                    {
                        sessionData.sessionData[i] = logonData;
                    }
                    else
                    {
                        sessionData.sessionData[i] = NULL;
                    }
                }
                SECUR32$LsaFreeReturnBuffer(logonSessionList);
                *data = sessionData;
            }
            else
            {
                status = STATUS_MEMORY_NOT_ALLOCATED;
            }
        }
        else
        {
            status = ADVAPI32$LsaNtStatusToWinError(status);
        }
    }
    return status;
}

void GetLogonTypeString(ULONG uLogonType, char **logonTypeString)
{
    char *types[10] = {
        "(0)",
        "(1)",
        "Interactive (2)",
        "Network (3)",
        "Batch (4)",
        "Service (5)",
        "(6)",
        "Unlock (7)",
        "Network_Cleartext (8)",
        "New_Credentials (9)"};

    *logonTypeString = MSVCRT$malloc(24 * sizeof(char));
    if (*logonTypeString == NULL)
    {
        return;
    }
    for (int i = 0; i < 10; i++)
    {
        if (i == uLogonType)
        {
            _strcpy(*logonTypeString, types[i]);
            return;
        }
    }
    _strcpy(*logonTypeString, "(unknown)\0");
}

void PrintLogonSessionData(SECURITY_LOGON_SESSION_DATA data, char **sessionString)
{
    char *fmt = "UserName                : %s\n"
                "Domain                  : %s\n"
                "LogonId                 : %lx:0x%lx\n"
                "Session                 : %ld\n"
                "UserSID                 : %s\n"
                "Authentication package  : %s\n"
                "LogonType               : %s\n"
                "LogonTime (UTC)         : %d/%d/%d %d:%d:%d\n"
                "LogonServer             : %s\n"
                "LogonServerDNSDomain    : %s\n"
                "UserPrincipalName       : %s\n";

    ANSI_STRING userName = {0};
    ANSI_STRING domain = {0};
    ANSI_STRING authPack = {0};
    ANSI_STRING logonServer = {0};
    ANSI_STRING logonServerDNSDomain = {0};
    ANSI_STRING upn = {0};

    NTDLL$RtlUnicodeStringToAnsiString(&userName, &data.UserName, TRUE);
    NTDLL$RtlUnicodeStringToAnsiString(&domain, &data.LogonDomain, TRUE);
    NTDLL$RtlUnicodeStringToAnsiString(&authPack, &data.AuthenticationPackage, TRUE);
    NTDLL$RtlUnicodeStringToAnsiString(&logonServer, &data.LogonServer, TRUE);
    NTDLL$RtlUnicodeStringToAnsiString(&logonServerDNSDomain, &data.DnsDomainName, TRUE);
    NTDLL$RtlUnicodeStringToAnsiString(&upn, &data.Upn, TRUE);
    char *sid = NULL;
    if (!ADVAPI32$ConvertSidToStringSidA(data.Sid, &sid))
    {
        sid = "-";
    }
    char *logonType = NULL;
    GetLogonTypeString(data.LogonType, &logonType);
    SYSTEMTIME st_utc = ConvertToSystemtime(data.LogonTime);
    int size = _strlen(fmt) +
               userName.Length +
               domain.Length +
               24 + 16 +
               _strlen(sid) +
               authPack.Length +
               32 +
               logonServer.Length +
               logonServerDNSDomain.Length +
               upn.Length + 1;
    if (logonType != NULL)
    {
        size += _strlen(logonType);
    }
    *sessionString = MSVCRT$malloc(size * sizeof(char));
    if (*sessionString == NULL)
    {
        goto end;
    }
    HRESULT result = _StringCchPrintfExA(*sessionString, size, NULL, NULL, STRSAFE_IGNORE_NULLS, fmt,
                                         userName.Buffer,
                                         domain.Buffer,
                                         data.LogonId.HighPart, data.LogonId.LowPart,
                                         data.Session,
                                         sid,
                                         authPack.Buffer,
                                         logonType,
                                         st_utc.wDay, st_utc.wMonth, st_utc.wYear, st_utc.wHour, st_utc.wMinute, st_utc.wSecond,
                                         logonServer.Buffer,
                                         logonServerDNSDomain.Buffer,
                                         upn.Buffer);
    if (FAILED(result))
    {
        MSVCRT$free(*sessionString);
        *sessionString = NULL;
    }
end:
    NTDLL$RtlFreeAnsiString(&userName);
    NTDLL$RtlFreeAnsiString(&domain);
    NTDLL$RtlFreeAnsiString(&authPack);
    NTDLL$RtlFreeAnsiString(&logonServer);
    NTDLL$RtlFreeAnsiString(&logonServerDNSDomain);
    NTDLL$RtlFreeAnsiString(&upn);
    if (logonType != NULL)
    {
        MSVCRT$free(logonType);
    }
}