#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include "common.h"

void execute_purge(WCHAR** dispatch, HANDLE hToken, LUID luid, BOOL currentLuid);
