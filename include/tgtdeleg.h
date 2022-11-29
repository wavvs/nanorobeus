#pragma once

#include <windows.h>
#include <lm.h>
#include "bofdefs.h"
#include "common.h"
#include "base64.h"
#include "msasn1.h"
#include "krb5.h"

void execute_tgtdeleg(WCHAR** dispatch, HANDLE hToken, char* spn);
PBYTE SearchOID(LPCVOID data, SIZE_T size);
PVOID MemorySearch(LPCVOID pattern, SIZE_T pSize, LPCVOID buf, SIZE_T bSize);
NTSTATUS KerberosDecrypt(DWORD keyUsage, KERB_ENCRYPTION_KEY* key, ASN1octetstring_t* in, ASN1octetstring_t* out);
NTSTATUS GetKeyFromCache(HANDLE hToken, char* target, LONG encType, PUCHAR* key, PULONG keySize);
LONG RequestApReq(char *spn, PUCHAR* apreq, PULONG apreqSize, BOOL checkDelegate);