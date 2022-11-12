#pragma once
#define SECURITY_WIN32

#include <windows.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <lm.h>
#include <security.h>

#if defined(BOF) || defined(BRC4)

// kernel32
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess(VOID);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI VOID WINAPI KERNEL32$SetLastError(DWORD dwErrCode);
WINBASEAPI int WINAPI KERNEL32$FileTimeToSystemTime(CONST FILETIME* lpFileTime, LPSYSTEMTIME lpSystemTime);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32FirstW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
WINBASEAPI WINBOOL WINAPI KERNEL32$Process32NextW(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD dwDesiredAccess, WINBOOL bInheritHandle, DWORD dwProcessId);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread();

// msvcrt
WINBASEAPI int __cdecl MSVCRT$strcmp(const char* _Str1, const char* _Str2);
WINBASEAPI size_t __cdecl MSVCRT$wcslen(const wchar_t* _Str);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char* _Str);
WINBASEAPI size_t __cdecl MSVCRT$wcstombs(char* mbstr, const wchar_t* wcstr, size_t count);
WINBASEAPI long __cdecl MSVCRT$strtol(const char* string, char** end_ptr, int base);
WINBASEAPI int __cdecl MSVCRT$wcscmp(const wchar_t* string1, const wchar_t* string2);
WINBASEAPI void* __cdecl MSVCRT$malloc(size_t size);
WINBASEAPI void* __cdecl MSVCRT$calloc(size_t num, size_t size);
WINBASEAPI void __cdecl MSVCRT$free(void* memblock);
WINBASEAPI void* __cdecl MSVCRT$memcpy(void* __restrict__ _Dst, const void* __restrict__ _Src, size_t _MaxCount);
WINBASEAPI void __cdecl MSVCRT$memset(void* dest, int c, size_t count);
WINBASEAPI int __cdecl MSVCRT$sprintf(char* __restrict__ _Dest, const char* __restrict__ _Format, ...);
WINBASEAPI size_t __cdecl MSVCRT$mbstowcs(wchar_t * __restrict__ _Dest,const char * __restrict__ _Source,size_t _MaxCount);

// advapi32
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass,
                                                      LPVOID TokenInformation, DWORD TokenInformationLength,
                                                      PDWORD ReturnLength);
WINADVAPI WINBOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID Sid, LPWSTR* StringSid);
WINADVAPI WINBOOL WINAPI ADVAPI32$AllocateAndInitializeSid(PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
                                                           BYTE nSubAuthorityCount, DWORD nSubAuthority0,
                                                           DWORD nSubAuthority1, DWORD nSubAuthority2,
                                                           DWORD nSubAuthority3, DWORD nSubAuthority4,
                                                           DWORD nSubAuthority5, DWORD nSubAuthority6,
                                                           DWORD nSubAuthority7, PSID* pSid);
WINADVAPI WINBOOL WINAPI ADVAPI32$EqualSid(PSID pSid1, PSID pSid2);
WINADVAPI PVOID WINAPI ADVAPI32$FreeSid(PSID pSid);
WINADVAPI WINBOOL WINAPI ADVAPI32$DuplicateToken(HANDLE ExistingTokenHandle,
                                                 SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                                                 PHANDLE DuplicateTokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$ImpersonateLoggedOnUser(HANDLE hToken);
WINADVAPI WINBOOL WINAPI ADVAPI32$LookupPrivilegeValueA(LPCSTR lpSystemName, LPCSTR lpName, PLUID lpLuid);
WINADVAPI WINBOOL WINAPI ADVAPI32$AdjustTokenPrivileges(HANDLE TokenHandle, BOOL DisableAllPrivileges,
                                                        PTOKEN_PRIVILEGES NewState, DWORD BufferLength,
                                                        PTOKEN_PRIVILEGES PreviousState, PDWORD ReturnLength);
WINADVAPI ULONG WINAPI ADVAPI32$LsaNtStatusToWinError(NTSTATUS Status);
WINADVAPI WINBOOL WINAPI ADVAPI32$RevertToSelf();
WINADVAPI WINBOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf,
                                                  PHANDLE TokenHandle);
WINADVAPI WINBOOL WINAPI ADVAPI32$CheckTokenMembership(HANDLE TokenHandle, PSID SidToCheck, PBOOL IsMember);

// secur32
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaGetLogonSessionData(PLUID LogonId,
                                                          PSECURITY_LOGON_SESSION_DATA* ppLogonSessionData);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaFreeReturnBuffer(PVOID Buffer);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaEnumerateLogonSessions(PULONG LogonSessionCount, PLUID* LogonSessionList);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaRegisterLogonProcess(PLSA_STRING LogonProcessName, PHANDLE LsaHandle,
                                                           PLSA_OPERATIONAL_MODE SecurityMode);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaLookupAuthenticationPackage(HANDLE LsaHandle, PLSA_STRING PackageName,
                                                                  PULONG AuthenticationPackage);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaCallAuthenticationPackage(HANDLE LsaHandle, ULONG AuthenticationPackage,
                                                                PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength,
                                                                PVOID* ProtocolReturnBuffer, PULONG ReturnBufferLength,
                                                                PNTSTATUS ProtocolStatus);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaDeregisterLogonProcess(HANDLE LsaHandle);
WINBASEAPI NTSTATUS WINAPI SECUR32$LsaConnectUntrusted(PHANDLE LsaHandle);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$AcquireCredentialsHandleA(SEC_CHAR* pszPrincipal, SEC_CHAR* pszPackage,
                                                                    unsigned __LONG32 fCredentialUse, void* pvLogonId,
                                                                    void* pAuthData, SEC_GET_KEY_FN pGetKeyFn,
                                                                    void* pvGetKeyArgument, PCredHandle phCredential,
                                                                    PTimeStamp ptsExpiry);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$InitializeSecurityContextA(
    PCredHandle phCredential, PCtxtHandle phContext, SEC_CHAR* pszTargetName, unsigned __LONG32 fContextReq,
    unsigned __LONG32 Reserved1, unsigned __LONG32 TargetDataRep, PSecBufferDesc pInput, unsigned __LONG32 Reserved2,
    PCtxtHandle phNewContext, PSecBufferDesc pOutput, unsigned __LONG32* pfContextAttr, PTimeStamp ptsExpiry);
WINBASEAPI SECURITY_STATUS WINAPI SECUR32$FreeContextBuffer(void *pvContextBuffer);
KSECDDDECLSPEC SECURITY_STATUS WINAPI SECUR32$DeleteSecurityContext(PCtxtHandle phContext);
KSECDDDECLSPEC SECURITY_STATUS WINAPI SECUR32$FreeCredentialsHandle(PCredHandle phCredential);
#else

#define KERNEL32$GetCurrentProcess GetCurrentProcess
#define KERNEL32$GetLastError GetLastError
#define KERNEL32$SetLastError SetLastError
#define KERNEL32$FileTimeToSystemTime FileTimeToSystemTime
#define KERNEL32$CreateToolhelp32Snapshot CreateToolhelp32Snapshot
#define KERNEL32$Process32FirstW Process32FirstW
#define KERNEL32$Process32NextW Process32NextW
#define KERNEL32$CloseHandle CloseHandle
#define KERNEL32$OpenProcess OpenProcess
#define KERNEL32$GetCurrentThread GetCurrentThread

#define MSVCRT$strcmp strcmp
#define MSVCRT$wcslen wcslen
#define MSVCRT$strlen strlen
#define MSVCRT$wcstombs wcstombs
#define MSVCRT$wcscmp wcscmp
#define MSVCRT$strtol strtol
#define MSVCRT$malloc malloc
#define MSVCRT$calloc calloc
#define MSVCRT$free free
#define MSVCRT$memcpy memcpy
#define MSVCRT$memset memset
#define MSVCRT$sprintf sprintf
#define MSVCRT$mbstowcs mbstowcs

#define ADVAPI32$OpenProcessToken OpenProcessToken
#define ADVAPI32$GetTokenInformation GetTokenInformation
#define ADVAPI32$ConvertSidToStringSidW ConvertSidToStringSidW
#define ADVAPI32$AllocateAndInitializeSid AllocateAndInitializeSid
#define ADVAPI32$EqualSid EqualSid
#define ADVAPI32$FreeSid FreeSid
#define ADVAPI32$DuplicateToken DuplicateToken
#define ADVAPI32$ImpersonateLoggedOnUser ImpersonateLoggedOnUser
#define ADVAPI32$LookupPrivilegeValueA LookupPrivilegeValueA
#define ADVAPI32$AdjustTokenPrivileges AdjustTokenPrivileges
#define ADVAPI32$LsaNtStatusToWinError LsaNtStatusToWinError
#define ADVAPI32$RevertToSelf RevertToSelf
#define ADVAPI32$OpenThreadToken OpenThreadToken
#define ADVAPI32$CheckTokenMembership CheckTokenMembership

#define SECUR32$LsaGetLogonSessionData LsaGetLogonSessionData
#define SECUR32$LsaFreeReturnBuffer LsaFreeReturnBuffer
#define SECUR32$LsaEnumerateLogonSessions LsaEnumerateLogonSessions
#define SECUR32$LsaRegisterLogonProcess LsaRegisterLogonProcess
#define SECUR32$LsaLookupAuthenticationPackage LsaLookupAuthenticationPackage
#define SECUR32$LsaCallAuthenticationPackage LsaCallAuthenticationPackage
#define SECUR32$LsaDeregisterLogonProcess LsaDeregisterLogonProcess
#define SECUR32$LsaConnectUntrusted LsaConnectUntrusted
#define SECUR32$AcquireCredentialsHandleA AcquireCredentialsHandleA
#define SECUR32$InitializeSecurityContextA InitializeSecurityContextA
#define SECUR32$FreeContextBuffer FreeContextBuffer
#define SECUR32$DeleteSecurityContext DeleteSecurityContext
#define SECUR32$FreeCredentialsHandle FreeCredentialsHandle
#endif