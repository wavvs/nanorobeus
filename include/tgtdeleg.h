#pragma once

#include <windows.h>
#include <lm.h>
#include "bofdefs.h"
#include "common.h"
#include "base64.h"

void execute_tgtdeleg(WCHAR** dispatch, char* spn);
void execute_tgtdeleg_getkey(WCHAR** dispatch, HANDLE hToken, char* target, LONG encType);