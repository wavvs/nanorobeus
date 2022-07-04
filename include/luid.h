#pragma once

#include <windows.h>
#include "common.h"

void execute_luid(WCHAR** dispatch, HANDLE hToken);
LUID* GetCurrentLUID(HANDLE TokenHandle);
