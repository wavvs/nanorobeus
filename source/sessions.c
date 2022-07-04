#include "sessions.h"

void execute_sessions(WCHAR** dispatch, HANDLE hToken, LUID luid, BOOL currentLuid) {
    BOOL highIntegrity = IsHighIntegrity(hToken);
    if (!highIntegrity && !currentLuid) {
        PRINT(dispatch, "[!] Not in high integrity.\n");
        return;
    }

    LOGON_SESSION_DATA sessionData;
    PSECURITY_LOGON_SESSION_DATA data;
    NTSTATUS status = GetLogonSessionData(luid, &sessionData);

    if (NT_SUCCESS(status)) {
        for (int i = 0; i < sessionData.sessionCount; i++) {
            data = sessionData.sessionData[i];
            if (data != NULL) {
                // PRINT(dispatch, "[%d] Session %d %x:0x%x %s\\%s %s:%s\n",
                //     i, data->Session, data->LogonId.HighPart, data->LogonId.LowPart,
                //     GetNarrowString(data->LogonDomain.Buffer),
                //     GetNarrowString(data->UserName.Buffer),
                //     GetNarrowString(data->AuthenticationPackage.Buffer),
                //     GetLogonTypeString(data->LogonType));
                PrintLogonSessionData(dispatch, *data);
                if (i != sessionData.sessionCount - 1) {
                    PRINT(dispatch, "\n\n");
                }
                SECUR32$LsaFreeReturnBuffer(data);
            }
        }
        MSVCRT$free(sessionData.sessionData);
    } else {
        PRINT(dispatch, "[!] execute_sessions GetLogonSessionData: %ld", status);
    }
}

NTSTATUS GetLogonSessionData(LUID luid, LOGON_SESSION_DATA* data) {
    LOGON_SESSION_DATA sessionData;
    PSECURITY_LOGON_SESSION_DATA logonData = NULL;
    NTSTATUS status;
    if (luid.LowPart != 0) {
        status = SECUR32$LsaGetLogonSessionData(&luid, &logonData);
        if (NT_SUCCESS(status)) {
            sessionData.sessionData = MSVCRT$calloc(1, sizeof(*sessionData.sessionData));
            if (sessionData.sessionData != NULL) {
                sessionData.sessionCount = 1;
                sessionData.sessionData[0] = logonData;
                *data = sessionData;
            } else {
                status = STATUS_MEMORY_NOT_ALLOCATED;
            }
        } else {
            status = ADVAPI32$LsaNtStatusToWinError(status);
        }
    } else {
        ULONG logonSessionCount;
        PLUID logonSessionList;
        status = SECUR32$LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList);
        if (NT_SUCCESS(status)) {
            sessionData.sessionData = MSVCRT$calloc(logonSessionCount, sizeof(*sessionData.sessionData));
            if (sessionData.sessionData != NULL) {
                sessionData.sessionCount = logonSessionCount;
                for (int i = 0; i < logonSessionCount; i++) {
                    LUID luid = logonSessionList[i];
                    status = SECUR32$LsaGetLogonSessionData(&luid, &logonData);
                    if (NT_SUCCESS(status)) {
                        sessionData.sessionData[i] = logonData;
                    } else {
                        sessionData.sessionData[i] = NULL;
                    }
                }
                SECUR32$LsaFreeReturnBuffer(logonSessionList);
                *data = sessionData;
            } else {
                status = STATUS_MEMORY_NOT_ALLOCATED;
            }
        } else {
            status = ADVAPI32$LsaNtStatusToWinError(status);
        }
    }
    return status;
}

char* GetLogonTypeString(ULONG uLogonType) {
    char* logonType = NULL;
    switch (uLogonType) {
        case LOGON32_LOGON_INTERACTIVE:
            logonType = "Interactive";
            break;
        case LOGON32_LOGON_NETWORK:
            logonType = "Network";
            break;
        case LOGON32_LOGON_BATCH:
            logonType = "Batch";
            break;
        case LOGON32_LOGON_SERVICE:
            logonType = "Service";
            break;
        case LOGON32_LOGON_UNLOCK:
            logonType = "Unlock";
            break;
        case LOGON32_LOGON_NETWORK_CLEARTEXT:
            logonType = "Network_Cleartext";
            break;
        case LOGON32_LOGON_NEW_CREDENTIALS:
            logonType = "New_Credentials";
            break;
        default:
            logonType = "(0)";
            break;
    }
    return logonType;
}

void PrintLogonSessionData(WCHAR** dispatch, SECURITY_LOGON_SESSION_DATA data) {
    WCHAR* sid = NULL;
    PRINT(dispatch, "UserName                : %.*s\n", data.UserName.Length / (int)sizeof(char),
          GetNarrowString(data.UserName.Buffer));
    PRINT(dispatch, "Domain                  : %.*s\n", data.LogonDomain.Length / (int)sizeof(char),
          GetNarrowString(data.LogonDomain.Buffer));
    PRINT(dispatch, "LogonId                 : %lx:0x%lx\n", data.LogonId.HighPart, data.LogonId.LowPart);
    PRINT(dispatch, "Session                 : %ld\n", data.Session);
    if (ADVAPI32$ConvertSidToStringSidW(data.Sid, &sid)) {
        PRINT(dispatch, "UserSID                 : %s\n", GetNarrowString(sid));
    } else {
        PRINT(dispatch, "UserSID                 : -\n");
    }
    PRINT(dispatch, "Authentication package  : %.*s\n", data.AuthenticationPackage.Length / (int)sizeof(char),
          GetNarrowString(data.AuthenticationPackage.Buffer));
    char* logonType = GetLogonTypeString(data.LogonType);
    PRINT(dispatch, "LogonType               : %s\n", logonType);
    SYSTEMTIME st_utc = ConvertToSystemtime(data.LogonTime);
    PRINT(dispatch, "LogonTime (UTC)         : %d/%d/%d %d:%d:%d\n", st_utc.wDay, st_utc.wMonth, st_utc.wYear,
          st_utc.wHour, st_utc.wMinute, st_utc.wSecond);
    PRINT(dispatch, "LogonServer             : %.*s\n", data.LogonServer.Length / (int)sizeof(char),
          GetNarrowString(data.LogonServer.Buffer));
    PRINT(dispatch, "LogonServerDNSDomain    : %.*s\n", data.DnsDomainName.Length / (int)sizeof(char),
          GetNarrowString(data.DnsDomainName.Buffer));
    PRINT(dispatch, "UserPrincipalName       : %.*s\n", data.Upn.Length / (int)sizeof(char),
          GetNarrowString(data.Upn.Buffer));
}