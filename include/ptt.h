#pragma once

#include <windows.h>
#include "common.h"
#include "base64.h"

void execute_ptt(WCHAR** dispatch, HANDLE hToken, char* ticket, LUID luid, BOOL currentLuid);