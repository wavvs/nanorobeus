#pragma once

#include <windows.h>
#include "bofdefs.h"
#include "common.h"
#include "luid.h"

void execute_sessions(WCHAR** dispatch, HANDLE hToken, LUID luid, BOOL currentLuid);
NTSTATUS GetLogonSessionData(LUID luid, LOGON_SESSION_DATA* data);
char* GetLogonTypeString(ULONG uLogonType);
void PrintLogonSessionData(WCHAR** dispatch, SECURITY_LOGON_SESSION_DATA data);