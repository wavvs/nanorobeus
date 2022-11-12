#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include "beacon.h"
#include "bofdefs.h"

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_MEMORY_NOT_ALLOCATED ((NTSTATUS)0xC00000A0L)
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) == 0)

typedef struct _LOGON_SESSION_DATA {
    PSECURITY_LOGON_SESSION_DATA* sessionData;
    ULONG sessionCount;
} LOGON_SESSION_DATA, PLOGON_SESSION_DATA;

enum KERB_ETYPE {
    DES_CBC_CRC = 1,
    DES_CBC_MD4 = 2,
    DES_CBC_MD5 = 3,
    DES3_CBC_MD5 = 5,
    DES3_CBC_SHA1 = 7,
    DSAWITHSHA1_CMSOID = 9,
    MD5WITHRSAENCRYPTION_CMSOID = 10,
    SHA1WITHRSAENCRYPTION_CMSOID = 11,
    RC2CBC_ENVOID = 12,
    RSAENCRYPTION_ENVOID = 13,
    RSAES_OAEP_ENV_OID = 14,
    DES3_CBC_SHA1_KD = 16,
    AES128_CTS_HMAC_SHA1 = 17,
    AES256_CTS_HMAC_SHA1 = 18,
    RC4_HMAC = 23,
    RC4_HMAC_EXP = 24,
    SUBKEY_KEYMATERIAL = 65,
    OLD_EXP = -135
};

HANDLE GetCurrentToken(DWORD DesiredAccess);
char* GetEncryptionTypeString(LONG encType);
SYSTEMTIME ConvertToSystemtime(LARGE_INTEGER li);
BOOL IsHighIntegrity(HANDLE TokenHandle);
BOOL IsSystem(HANDLE TokenHandle);
NTSTATUS GetLsaHandle(HANDLE hProcessToken, BOOL highIntegrity, HANDLE* hLsa);
int GetProcessIdByName(WCHAR* processName);
BOOL ElevateToSystem();
char* GetNarrowString(WCHAR* src);
char* GetNarrowStringFromUnicode(UNICODE_STRING src);
WCHAR* GetWideString(char* src);