#include "krb5.h"
#include "bofdefs.h"

// Copyright (c) Microsoft Corporation

static int ASN1CALL ASN1Enc_KERB_CRED(ASN1encoding_t enc, ASN1uint32_t tag, KERB_CRED* val);
static int ASN1CALL ASN1Dec_KERB_AP_REQUEST(ASN1decoding_t dec, ASN1uint32_t tag, KERB_AP_REQUEST* val);
static int ASN1CALL ASN1Enc_KERB_CRED_tickets(ASN1encoding_t enc, ASN1uint32_t tag, PKERB_CRED_tickets* val);
static int ASN1CALL ASN1Enc_KERB_TICKET(ASN1encoding_t enc, ASN1uint32_t tag, KERB_TICKET* val);
static int ASN1CALL ASN1Enc_KERB_PRINCIPAL_NAME(ASN1encoding_t enc, ASN1uint32_t tag, KERB_PRINCIPAL_NAME* val);
static int ASN1CALL ASN1Enc_KERB_PRINCIPAL_NAME_name_string(ASN1encoding_t enc, ASN1uint32_t tag,
                                                            PKERB_PRINCIPAL_NAME_name_string* val);
static int ASN1CALL ASN1Enc_KERB_ENCRYPTED_DATA(ASN1encoding_t enc, ASN1uint32_t tag, KERB_ENCRYPTED_DATA* val);
static int ASN1CALL ASN1Enc_PKERB_TICKET_EXTENSIONS(ASN1encoding_t enc, ASN1uint32_t tag,
                                                    PPKERB_TICKET_EXTENSIONS* val);
static int ASN1CALL ASN1Enc_PKERB_TICKET_EXTENSIONS_Seq(ASN1encoding_t enc, ASN1uint32_t tag,
                                                        PKERB_TICKET_EXTENSIONS_Seq* val);
static int ASN1CALL ASN1Dec_KERB_TICKET(ASN1decoding_t dec, ASN1uint32_t tag, KERB_TICKET* val);
static int ASN1CALL ASN1Dec_KERB_PRINCIPAL_NAME(ASN1decoding_t dec, ASN1uint32_t tag, KERB_PRINCIPAL_NAME* val);
static int ASN1CALL ASN1Dec_KERB_PRINCIPAL_NAME_name_string(ASN1decoding_t dec, ASN1uint32_t tag,
                                                            PKERB_PRINCIPAL_NAME_name_string* val);
static int ASN1CALL ASN1Dec_KERB_ENCRYPTED_DATA(ASN1decoding_t dec, ASN1uint32_t tag, KERB_ENCRYPTED_DATA* val);
static int ASN1CALL ASN1Dec_PKERB_TICKET_EXTENSIONS(ASN1decoding_t dec, ASN1uint32_t tag,
                                                    PPKERB_TICKET_EXTENSIONS* val);
static int ASN1CALL ASN1Dec_PKERB_TICKET_EXTENSIONS_Seq(ASN1decoding_t dec, ASN1uint32_t tag,
                                                        PKERB_TICKET_EXTENSIONS_Seq* val);
static int ASN1CALL ASN1Dec_KERB_AUTHENTICATOR(ASN1decoding_t dec, ASN1uint32_t tag, KERB_AUTHENTICATOR* val);
static int ASN1CALL ASN1Dec_KERB_CHECKSUM(ASN1decoding_t dec, ASN1uint32_t tag, KERB_CHECKSUM* val);
static int ASN1CALL ASN1Dec_KERB_ENCRYPTION_KEY(ASN1decoding_t dec, ASN1uint32_t tag, KERB_ENCRYPTION_KEY* val);
static int ASN1CALL ASN1Dec_PKERB_AUTHORIZATION_DATA(ASN1decoding_t dec, ASN1uint32_t tag,
                                                     PPKERB_AUTHORIZATION_DATA* val);
static int ASN1CALL ASN1Dec_PKERB_AUTHORIZATION_DATA_Seq(ASN1decoding_t dec, ASN1uint32_t tag,
                                                         PKERB_AUTHORIZATION_DATA_Seq* val);
static int ASN1CALL ASN1Dec_KERB_CRED(ASN1decoding_t dec, ASN1uint32_t tag, KERB_CRED* val);
static int ASN1CALL ASN1Dec_KERB_CRED_tickets(ASN1decoding_t dec, ASN1uint32_t tag, PKERB_CRED_tickets* val);
static void ASN1CALL ASN1Free_KERB_AP_REQUEST(KERB_AP_REQUEST* val);
static void ASN1CALL ASN1Free_KERB_TICKET(KERB_TICKET* val);
static void ASN1CALL ASN1Free_KERB_ENCRYPTED_DATA(KERB_ENCRYPTED_DATA* val);
static void ASN1CALL ASN1Free_KERB_PRINCIPAL_NAME(KERB_PRINCIPAL_NAME* val);
static void ASN1CALL ASN1Free_KERB_PRINCIPAL_NAME_name_string(PKERB_PRINCIPAL_NAME_name_string* val);
static void ASN1CALL ASN1Free_PKERB_TICKET_EXTENSIONS(PPKERB_TICKET_EXTENSIONS* val);
static void ASN1CALL ASN1Free_PKERB_TICKET_EXTENSIONS_Seq(PKERB_TICKET_EXTENSIONS_Seq* val);
static void ASN1CALL ASN1Free_KERB_AUTHENTICATOR(KERB_AUTHENTICATOR* val);
static void ASN1CALL ASN1Free_PKERB_AUTHORIZATION_DATA_Seq(PKERB_AUTHORIZATION_DATA_Seq* val);
static void ASN1CALL ASN1Free_PKERB_AUTHORIZATION_DATA(PPKERB_AUTHORIZATION_DATA* val);
static void ASN1CALL ASN1Free_KERB_CHECKSUM(KERB_CHECKSUM* val);
static void ASN1CALL ASN1Free_KERB_REPLY_KEY_PACKAGE2(KERB_REPLY_KEY_PACKAGE2* val);
static void ASN1CALL ASN1Free_KERB_ENCRYPTION_KEY(KERB_ENCRYPTION_KEY* val);
static void ASN1CALL ASN1Free_KERB_CRED(KERB_CRED* val);
static void ASN1CALL ASN1Free_KERB_CRED_tickets(PKERB_CRED_tickets* val);

// Modern Windows has 75 PDUs
typedef ASN1BerEncFun_t ASN1EncFun_t;
ASN1EncFun_t encfntab[49] = {
    NULL,  //(ASN1EncFun_t)ASN1Enc_PKERB_AUTHORIZATION_DATA_LIST,
    NULL,  //(ASN1EncFun_t)ASN1Enc_PKERB_IF_RELEVANT_AUTH_DATA,
    NULL,  //(ASN1EncFun_t)ASN1Enc_PKERB_PREAUTH_DATA_LIST,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ENCRYPTED_PRIV,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ENCRYPTED_CRED,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ERROR,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ENCRYPTED_DATA,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ENCRYPTION_KEY,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_CHECKSUM,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ENCRYPTED_TIMESTAMP,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_SALTED_ENCRYPTED_TIMESTAMP,
    NULL,  //(ASN1EncFun_t)ASN1Enc_PKERB_ETYPE_INFO,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_TGT_REQUEST,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_PKCS_SIGNATURE,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_PA_PK_AS_REP,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_REPLY_KEY_PACKAGE2,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_REPLY_KEY_PACKAGE,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_KDC_DH_KEY_INFO,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_PA_PK_AS_REQ,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_DH_PARAMTER,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_KDC_ISSUED_AUTH_DATA,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_PA_SERV_REFERRAL,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_PA_PAC_REQUEST,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_CHANGE_PASSWORD_DATA,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ERROR_METHOD_DATA,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_EXT_ERROR,
    NULL,  //(ASN1EncFun_t)ASN1Enc_TYPED_DATA,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_PA_FOR_USER,
    (ASN1EncFun_t)ASN1Enc_KERB_TICKET,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ENCRYPTED_TICKET,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_AUTHENTICATOR,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_AP_REQUEST,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_AP_REPLY,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ENCRYPTED_AP_REPLY,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_SAFE_MESSAGE,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_PRIV_MESSAGE,
    (ASN1EncFun_t)ASN1Enc_KERB_CRED,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_TGT_REPLY,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_SIGNED_REPLY_KEY_PACKAGE,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_AUTH_PACKAGE,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_MARSHALLED_REQUEST_BODY,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_AS_REPLY,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_TGS_REPLY,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ENCRYPTED_AS_REPLY,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_ENCRYPTED_TGS_REPLY,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_PA_PK_AS_REP2,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_AS_REQUEST,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_TGS_REQUEST,
    NULL,  //(ASN1EncFun_t)ASN1Enc_KERB_PA_PK_AS_REQ2,
};

typedef ASN1BerDecFun_t ASN1DecFun_t;
ASN1DecFun_t decfntab[49] = {
    NULL,  //(ASN1DecFun_t)ASN1Dec_PKERB_AUTHORIZATION_DATA_LIST,
    NULL,  //(ASN1DecFun_t)ASN1Dec_PKERB_IF_RELEVANT_AUTH_DATA,
    NULL,  //(ASN1DecFun_t)ASN1Dec_PKERB_PREAUTH_DATA_LIST,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_ENCRYPTED_PRIV,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_ENCRYPTED_CRED,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_ERROR,
    (ASN1DecFun_t)ASN1Dec_KERB_ENCRYPTED_DATA,
    (ASN1DecFun_t)ASN1Dec_KERB_ENCRYPTION_KEY,
    (ASN1DecFun_t)ASN1Dec_KERB_CHECKSUM,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_ENCRYPTED_TIMESTAMP,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_SALTED_ENCRYPTED_TIMESTAMP,
    NULL,  //(ASN1DecFun_t)ASN1Dec_PKERB_ETYPE_INFO,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_TGT_REQUEST,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_PKCS_SIGNATURE,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_PA_PK_AS_REP,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_REPLY_KEY_PACKAGE2,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_REPLY_KEY_PACKAGE,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_KDC_DH_KEY_INFO,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_PA_PK_AS_REQ,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_DH_PARAMTER,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_KDC_ISSUED_AUTH_DATA,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_PA_SERV_REFERRAL,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_PA_PAC_REQUEST,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_CHANGE_PASSWORD_DATA,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_ERROR_METHOD_DATA,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_EXT_ERROR,
    NULL,  //(ASN1DecFun_t)ASN1Dec_TYPED_DATA,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_PA_FOR_USER,
    (ASN1DecFun_t)ASN1Dec_KERB_TICKET,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_ENCRYPTED_TICKET,
    (ASN1DecFun_t)ASN1Dec_KERB_AUTHENTICATOR,
    (ASN1DecFun_t)ASN1Dec_KERB_AP_REQUEST,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_AP_REPLY,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_ENCRYPTED_AP_REPLY,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_SAFE_MESSAGE,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_PRIV_MESSAGE,
    (ASN1DecFun_t)ASN1Dec_KERB_CRED,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_TGT_REPLY,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_SIGNED_REPLY_KEY_PACKAGE,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_AUTH_PACKAGE,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_MARSHALLED_REQUEST_BODY,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_AS_REPLY,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_TGS_REPLY,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_ENCRYPTED_AS_REPLY,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_ENCRYPTED_TGS_REPLY,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_PA_PK_AS_REP2,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_AS_REQUEST,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_TGS_REQUEST,
    NULL,  //(ASN1DecFun_t)ASN1Dec_KERB_PA_PK_AS_REQ2,
};

ASN1FreeFun_t freefntab[49] = {
    NULL,  //(ASN1FreeFun_t)ASN1Free_PKERB_AUTHORIZATION_DATA_LIST,
    NULL,  //(ASN1FreeFun_t)ASN1Free_PKERB_IF_RELEVANT_AUTH_DATA,
    NULL,  //(ASN1FreeFun_t)ASN1Free_PKERB_PREAUTH_DATA_LIST,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_ENCRYPTED_PRIV,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_ENCRYPTED_CRED,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_ERROR,
    (ASN1FreeFun_t)ASN1Free_KERB_ENCRYPTED_DATA,
    (ASN1FreeFun_t)ASN1Free_KERB_ENCRYPTION_KEY,
    (ASN1FreeFun_t)ASN1Free_KERB_CHECKSUM,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_ENCRYPTED_TIMESTAMP,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_SALTED_ENCRYPTED_TIMESTAMP,
    NULL,  //(ASN1FreeFun_t)ASN1Free_PKERB_ETYPE_INFO,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_TGT_REQUEST,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_PKCS_SIGNATURE,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_PA_PK_AS_REP,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_REPLY_KEY_PACKAGE2,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_REPLY_KEY_PACKAGE,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_KDC_DH_KEY_INFO,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_PA_PK_AS_REQ,
    (ASN1FreeFun_t)NULL,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_KDC_ISSUED_AUTH_DATA,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_PA_SERV_REFERRAL,
    (ASN1FreeFun_t)NULL,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_CHANGE_PASSWORD_DATA,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_ERROR_METHOD_DATA,
    (ASN1FreeFun_t)NULL,
    NULL,  //(ASN1FreeFun_t)ASN1Free_TYPED_DATA,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_PA_FOR_USER,
    (ASN1FreeFun_t)ASN1Free_KERB_TICKET,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_ENCRYPTED_TICKET,
    (ASN1FreeFun_t)ASN1Free_KERB_AUTHENTICATOR,
    (ASN1FreeFun_t)ASN1Free_KERB_AP_REQUEST,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_AP_REPLY,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_ENCRYPTED_AP_REPLY,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_SAFE_MESSAGE,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_PRIV_MESSAGE,
    (ASN1FreeFun_t)ASN1Free_KERB_CRED,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_TGT_REPLY,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_SIGNED_REPLY_KEY_PACKAGE,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_AUTH_PACKAGE,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_MARSHALLED_REQUEST_BODY,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_AS_REPLY,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_TGS_REPLY,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_ENCRYPTED_AS_REPLY,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_ENCRYPTED_TGS_REPLY,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_PA_PK_AS_REP2,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_AS_REQUEST,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_TGS_REQUEST,
    NULL,  //(ASN1FreeFun_t)ASN1Free_KERB_PA_PK_AS_REQ2,
};

ULONG sizetab[49] = {
    0,  // SIZE_KRB5_Module_PDU_0,
    0,  // SIZE_KRB5_Module_PDU_1,
    0,  // SIZE_KRB5_Module_PDU_2,
    0,  // SIZE_KRB5_Module_PDU_3,
    0,  // SIZE_KRB5_Module_PDU_4,
    0,  // SIZE_KRB5_Module_PDU_5,
    SIZE_KRB5_Module_PDU_6,
    SIZE_KRB5_Module_PDU_7,
    0,  // SIZE_KRB5_Module_PDU_8,
    0,  // SIZE_KRB5_Module_PDU_9,
    0,  // SIZE_KRB5_Module_PDU_10,
    0,  // SIZE_KRB5_Module_PDU_11,
    0,  // SIZE_KRB5_Module_PDU_12,
    0,  // SIZE_KRB5_Module_PDU_13,
    0,  // SIZE_KRB5_Module_PDU_14,
    SIZE_KRB5_Module_PDU_15,
    0,  // SIZE_KRB5_Module_PDU_16,
    0,  // SIZE_KRB5_Module_PDU_17,
    0,  // SIZE_KRB5_Module_PDU_18,
    0,  // SIZE_KRB5_Module_PDU_19,
    0,  // SIZE_KRB5_Module_PDU_20,
    0,  // SIZE_KRB5_Module_PDU_21,
    0,  // SIZE_KRB5_Module_PDU_22,
    0,  // SIZE_KRB5_Module_PDU_23,
    0,  // SIZE_KRB5_Module_PDU_24,
    0,  // SIZE_KRB5_Module_PDU_25,
    0,  // SIZE_KRB5_Module_PDU_26,
    0,  // SIZE_KRB5_Module_PDU_27,
    SIZE_KRB5_Module_PDU_28,
    0,  // SIZE_KRB5_Module_PDU_29,
    SIZE_KRB5_Module_PDU_30,
    SIZE_KRB5_Module_PDU_31,
    0,  // SIZE_KRB5_Module_PDU_32,
    0,  // SIZE_KRB5_Module_PDU_33,
    0,  // SIZE_KRB5_Module_PDU_34,
    0,  // SIZE_KRB5_Module_PDU_35,
    SIZE_KRB5_Module_PDU_36,
    0,  // SIZE_KRB5_Module_PDU_37,
    0,  // SIZE_KRB5_Module_PDU_38,
    0,  // SIZE_KRB5_Module_PDU_39,
    0,  // SIZE_KRB5_Module_PDU_40,
    0,  // SIZE_KRB5_Module_PDU_41,
    0,  // SIZE_KRB5_Module_PDU_42,
    0,  // SIZE_KRB5_Module_PDU_43,
    0,  // SIZE_KRB5_Module_PDU_44,
    0,  // SIZE_KRB5_Module_PDU_45,
    0,  // SIZE_KRB5_Module_PDU_46,
    0,  // SIZE_KRB5_Module_PDU_47,
    0,  // SIZE_KRB5_Module_PDU_48,
};

ASN1module_t ASN1CALL KRB5_Module_Startup(void) {
    return MSASN1$ASN1_CreateModule(0x10000, ASN1_BER_RULE_DER, ASN1FLAGS_NOASSERT, 49,
                                    (const ASN1GenericFun_t*)encfntab, (const ASN1GenericFun_t*)decfntab, freefntab,
                                    sizetab, 0x3562726b);
}

void ASN1CALL KRB5_Module_Cleanup(ASN1module_t module) { MSASN1$ASN1_CloseModule(module); }

KERBERR KerbInitAsn(ASN1module_t module, ASN1encoding_t* pEnc, ASN1decoding_t* pDec) {
    KERBERR KerbErr = KRB_ERR_GENERIC;
    ASN1error_e Asn1Err;
    if (pEnc != NULL) {
        Asn1Err = MSASN1$ASN1_CreateEncoder(module, pEnc, NULL, 0, NULL);
    } else {
        Asn1Err = MSASN1$ASN1_CreateDecoder(module, pDec, NULL, 0, NULL);
    }

    if (ASN1_SUCCESS != Asn1Err) {
        goto Cleanup;
    }
    KerbErr = KDC_ERR_NONE;
Cleanup:
    return KerbErr;
}

void KerbTermAsn(ASN1encoding_t pEnc, ASN1decoding_t pDec) {
    if (pEnc != NULL) {
        MSASN1$ASN1_CloseEncoder(pEnc);
    } else if (pDec != NULL) {
        MSASN1$ASN1_CloseDecoder(pDec);
    }
}

KERBERR NTAPI KerbPackData(ASN1module_t module, PVOID Data, ULONG PduValue, PULONG DataSize, PUCHAR* EncodedData) {
    KERBERR KerbErr = KDC_ERR_NONE;
    ASN1encoding_t pEnc = NULL;
    ASN1error_e Asn1Err;

    KerbErr = KerbInitAsn(module, &pEnc, NULL);
    if (!KERB_SUCCESS(KerbErr)) {
        goto Cleanup;
    }

    Asn1Err = MSASN1$ASN1_Encode(pEnc, Data, PduValue, ASN1ENCODE_ALLOCATEBUFFER, NULL, 0);

    if (!ASN1_SUCCEEDED(Asn1Err)) {
        KerbErr = KRB_ERR_GENERIC;
        goto Cleanup;
    } else {
        *EncodedData = KERNEL32$LocalAlloc(LPTR, pEnc->len);
        if (*EncodedData == NULL) {
            KerbErr = KRB_ERR_GENERIC;
            *DataSize = 0;
        } else {
            MSVCRT$memcpy(*EncodedData, pEnc->buf, pEnc->len);
            *DataSize = pEnc->len;
        }
        MSASN1$ASN1_FreeEncoded(pEnc, pEnc->buf);
    }

Cleanup:
    KerbTermAsn(pEnc, NULL);
    return KerbErr;
}

KERBERR NTAPI KerbUnpackData(ASN1module_t module, PUCHAR Data, ULONG DataSize, ULONG PduValue, PVOID* DecodedData) {
    KERBERR KerbErr = KDC_ERR_NONE;
    ASN1decoding_t pDec = NULL;
    ASN1error_e Asn1Err;

    if ((DataSize == 0) || (Data == NULL)) {
        return KRB_ERR_GENERIC;
    }

    KerbErr = KerbInitAsn(module, NULL, &pDec);
    if (!KERB_SUCCESS(KerbErr)) {
        return KerbErr;
    }
    *DecodedData = NULL;
    Asn1Err = MSASN1$ASN1_Decode(pDec, DecodedData, PduValue, ASN1DECODE_SETBUFFER, (BYTE*)Data, DataSize);
    if (!ASN1_SUCCEEDED(Asn1Err)) {
        if ((ASN1_ERR_BADARGS == Asn1Err) || (ASN1_ERR_EOD == Asn1Err)) {
            KerbErr = KDC_ERR_MORE_DATA;
        } else {
            KerbErr = KRB_ERR_GENERIC;
        }
        *DecodedData = NULL;
    }

    KerbTermAsn(NULL, pDec);

    return KerbErr;
}

void KerbFreeData(ASN1module_t module, ULONG PduValue, PVOID Data) {
    ASN1decoding_t pDec = NULL;

    KERBERR KerbErr;
    KerbErr = KerbInitAsn(module, NULL, &pDec);

    if (KERB_SUCCESS(KerbErr)) {
        MSASN1$ASN1_FreeDecoded(pDec, Data, PduValue);
        KerbTermAsn(NULL, pDec);
    }
}

static int ASN1CALL ASN1Enc_KERB_CRED(ASN1encoding_t enc, ASN1uint32_t tag, KERB_CRED* val) {
    ASN1uint32_t nExplTagLenOff0;
    ASN1uint32_t nLenOff;
    ASN1uint32_t nLenOff0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000016, &nExplTagLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x10, &nLenOff)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncS32(enc, 0x2, (val)->version)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncS32(enc, 0x2, (val)->message_type)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if (!ASN1Enc_KERB_CRED_tickets(enc, 0, &(val)->tickets)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000003, &nLenOff0)) return 0;
    if (!ASN1Enc_KERB_ENCRYPTED_DATA(enc, 0, &(val)->encrypted_part)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nExplTagLenOff0)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_AP_REQUEST(ASN1decoding_t dec, ASN1uint32_t tag, KERB_AP_REQUEST* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t pExplTagDec0;
    ASN1octet_t* pbExplTagDataEnd0;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x4000000e, &pExplTagDec0, &pbExplTagDataEnd0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(pExplTagDec0, 0x10, &dd, &di)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->version)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->message_type)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000002, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecBitString(dd0, 0x3, &(val)->ap_options)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000003, &dd0, &di0)) return 0;
    if (!ASN1Dec_KERB_TICKET(dd0, 0, &(val)->ticket)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000004, &dd0, &di0)) return 0;
    if (!ASN1Dec_KERB_ENCRYPTED_DATA(dd0, 0, &(val)->authenticator)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(pExplTagDec0, dd, di)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, pExplTagDec0, pbExplTagDataEnd0)) return 0;
    return 1;
}

static int ASN1CALL ASN1Enc_KERB_CRED_tickets(ASN1encoding_t enc, ASN1uint32_t tag, PKERB_CRED_tickets* val) {
    ASN1uint32_t nLenOff0;
    PKERB_CRED_tickets f;
    ASN1uint32_t nLenOff;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, tag ? tag : 0x80000002, &nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x10, &nLenOff)) return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1Enc_KERB_TICKET(enc, 0, &f->value)) return 0;
    }
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    return 1;
}

static int ASN1CALL ASN1Enc_KERB_TICKET(ASN1encoding_t enc, ASN1uint32_t tag, KERB_TICKET* val) {
    ASN1uint32_t nExplTagLenOff0;
    ASN1uint32_t nLenOff;
    ASN1uint32_t nLenOff0;
    ASN1uint32_t t;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, tag ? tag : 0x40000001, &nExplTagLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x10, &nLenOff)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncS32(enc, 0x2, (val)->ticket_version)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    t = KERNEL32$lstrlenA((val)->realm);
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0)) return 0;
    if (!MSASN1$ASN1DEREncCharString(enc, 0x1b, t, (val)->realm)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000002, &nLenOff0)) return 0;
    if (!ASN1Enc_KERB_PRINCIPAL_NAME(enc, 0, &(val)->server_name)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000003, &nLenOff0)) return 0;
    if (!ASN1Enc_KERB_ENCRYPTED_DATA(enc, 0, &(val)->encrypted_part)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if ((val)->o[0] & 0x80) {
        if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000004, &nLenOff0)) return 0;
        if (!ASN1Enc_PKERB_TICKET_EXTENSIONS(enc, 0, &(val)->ticket_extensions)) return 0;
        if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    }
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nExplTagLenOff0)) return 0;
    return 1;
}

static int ASN1CALL ASN1Enc_KERB_PRINCIPAL_NAME(ASN1encoding_t enc, ASN1uint32_t tag, KERB_PRINCIPAL_NAME* val) {
    ASN1uint32_t nLenOff;
    ASN1uint32_t nLenOff0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncS32(enc, 0x2, (val)->name_type)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if (!ASN1Enc_KERB_PRINCIPAL_NAME_name_string(enc, 0, &(val)->name_string)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff)) return 0;
    return 1;
}

static int ASN1CALL ASN1Enc_KERB_PRINCIPAL_NAME_name_string(ASN1encoding_t enc, ASN1uint32_t tag,
                                                            PKERB_PRINCIPAL_NAME_name_string* val) {
    ASN1uint32_t nLenOff0;
    PKERB_PRINCIPAL_NAME_name_string f;
    ASN1uint32_t nLenOff;
    ASN1uint32_t t;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, tag ? tag : 0x80000001, &nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x10, &nLenOff)) return 0;
    for (f = *val; f; f = f->next) {
        t = KERNEL32$lstrlenA(f->value);
        if (!MSASN1$ASN1DEREncCharString(enc, 0x1b, t, f->value)) return 0;
    }
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    return 1;
}

static int ASN1CALL ASN1Enc_KERB_ENCRYPTED_DATA(ASN1encoding_t enc, ASN1uint32_t tag, KERB_ENCRYPTED_DATA* val) {
    ASN1uint32_t nLenOff;
    ASN1uint32_t nLenOff0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncS32(enc, 0x2, (val)->encryption_type)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if ((val)->o[0] & 0x80) {
        if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0)) return 0;
        if (!MSASN1$ASN1BEREncS32(enc, 0x2, (val)->version)) return 0;
        if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    }
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000002, &nLenOff0)) return 0;
    if (!MSASN1$ASN1DEREncOctetString(enc, 0x4, ((val)->cipher_text).length, ((val)->cipher_text).value)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff)) return 0;
    return 1;
}

static int ASN1CALL ASN1Enc_PKERB_TICKET_EXTENSIONS(ASN1encoding_t enc, ASN1uint32_t tag,
                                                    PPKERB_TICKET_EXTENSIONS* val) {
    PPKERB_TICKET_EXTENSIONS f;
    ASN1uint32_t nLenOff;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff)) return 0;
    for (f = *val; f; f = f->next) {
        if (!ASN1Enc_PKERB_TICKET_EXTENSIONS_Seq(enc, 0, &f->value)) return 0;
    }
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff)) return 0;
    return 1;
}

static int ASN1CALL ASN1Enc_PKERB_TICKET_EXTENSIONS_Seq(ASN1encoding_t enc, ASN1uint32_t tag,
                                                        PKERB_TICKET_EXTENSIONS_Seq* val) {
    ASN1uint32_t nLenOff;
    ASN1uint32_t nLenOff0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, tag ? tag : 0x10, &nLenOff)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000000, &nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncS32(enc, 0x2, (val)->te_type)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncExplicitTag(enc, 0x80000001, &nLenOff0)) return 0;
    if (!MSASN1$ASN1DEREncOctetString(enc, 0x4, ((val)->te_data).length, ((val)->te_data).value)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff0)) return 0;
    if (!MSASN1$ASN1BEREncEndOfContents(enc, nLenOff)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_TICKET(ASN1decoding_t dec, ASN1uint32_t tag, KERB_TICKET* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t pExplTagDec0;
    ASN1octet_t* pbExplTagDataEnd0;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    ASN1uint32_t t;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000001, &pExplTagDec0, &pbExplTagDataEnd0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(pExplTagDec0, 0x10, &dd, &di)) return 0;
    MSVCRT$memset((val)->o, 0, 1);
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->ticket_version)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecZeroCharString(dd0, 0x1b, &(val)->realm)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000002, &dd0, &di0)) return 0;
    if (!ASN1Dec_KERB_PRINCIPAL_NAME(dd0, 0, &(val)->server_name)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000003, &dd0, &di0)) return 0;
    if (!ASN1Dec_KERB_ENCRYPTED_DATA(dd0, 0, &(val)->encrypted_part)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    MSASN1$ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000004) {
        (val)->o[0] |= 0x80;
        if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000004, &dd0, &di0)) return 0;
        if (!ASN1Dec_PKERB_TICKET_EXTENSIONS(dd0, 0, &(val)->ticket_extensions)) return 0;
        if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    }
    if (!MSASN1$ASN1BERDecEndOfContents(pExplTagDec0, dd, di)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, pExplTagDec0, pbExplTagDataEnd0)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_PRINCIPAL_NAME(ASN1decoding_t dec, ASN1uint32_t tag, KERB_PRINCIPAL_NAME* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->name_type)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!ASN1Dec_KERB_PRINCIPAL_NAME_name_string(dd, 0, &(val)->name_string)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd, di)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_PRINCIPAL_NAME_name_string(ASN1decoding_t dec, ASN1uint32_t tag,
                                                            PKERB_PRINCIPAL_NAME_name_string* val) {
    PKERB_PRINCIPAL_NAME_name_string* f;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1uint32_t t;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x80000001, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd0, 0x10, &dd, &di)) return 0;
    f = val;
    while (MSASN1$ASN1BERDecNotEndOfContents(dd, di)) {
        if (!MSASN1$ASN1BERDecPeekTag(dd, &t)) return 0;
        if (!(*f = (PKERB_PRINCIPAL_NAME_name_string)MSASN1$ASN1DecAlloc(dd, sizeof(**f)))) return 0;
        if (!MSASN1$ASN1BERDecZeroCharString(dd, 0x1b, &(*f)->value)) return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!MSASN1$ASN1BERDecEndOfContents(dd0, dd, di)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd0, di0)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_ENCRYPTED_DATA(ASN1decoding_t dec, ASN1uint32_t tag, KERB_ENCRYPTED_DATA* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    ASN1uint32_t t;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di)) return 0;
    MSVCRT$memset((val)->o, 0, 1);
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->encryption_type)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    MSASN1$ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000001) {
        (val)->o[0] |= 0x80;
        if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0)) return 0;
        if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->version)) return 0;
        if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    }
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000002, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecOctetString(dd0, 0x4, &(val)->cipher_text)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd, di)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_PKERB_TICKET_EXTENSIONS(ASN1decoding_t dec, ASN1uint32_t tag,
                                                    PPKERB_TICKET_EXTENSIONS* val) {
    PPKERB_TICKET_EXTENSIONS* f;
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1uint32_t t;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di)) return 0;
    f = val;
    while (MSASN1$ASN1BERDecNotEndOfContents(dd, di)) {
        if (!MSASN1$ASN1BERDecPeekTag(dd, &t)) return 0;
        if (!(*f = (PPKERB_TICKET_EXTENSIONS)MSASN1$ASN1DecAlloc(dd, sizeof(**f)))) return 0;
        if (!ASN1Dec_PKERB_TICKET_EXTENSIONS_Seq(dd, 0, &(*f)->value)) return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd, di)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_PKERB_TICKET_EXTENSIONS_Seq(ASN1decoding_t dec, ASN1uint32_t tag,
                                                        PKERB_TICKET_EXTENSIONS_Seq* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->te_type)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecOctetString(dd0, 0x4, &(val)->te_data)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd, di)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_AUTHENTICATOR(ASN1decoding_t dec, ASN1uint32_t tag, KERB_AUTHENTICATOR* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t pExplTagDec0;
    ASN1octet_t* pbExplTagDataEnd0;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    ASN1uint32_t t;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000002, &pExplTagDec0, &pbExplTagDataEnd0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(pExplTagDec0, 0x10, &dd, &di)) return 0;
    MSVCRT$memset((val)->o, 0, 1);
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->authenticator_version)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecZeroCharString(dd0, 0x1b, &(val)->client_realm)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000002, &dd0, &di0)) return 0;
    if (!ASN1Dec_KERB_PRINCIPAL_NAME(dd0, 0, &(val)->client_name)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    MSASN1$ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000003) {
        (val)->o[0] |= 0x80;
        if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000003, &dd0, &di0)) return 0;
        if (!ASN1Dec_KERB_CHECKSUM(dd0, 0, &(val)->checksum)) return 0;
        if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    }
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000004, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->client_usec)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000005, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecGeneralizedTime(dd0, 0x18, &(val)->client_time)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    MSASN1$ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000006) {
        (val)->o[0] |= 0x40;
        if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000006, &dd0, &di0)) return 0;
        if (!ASN1Dec_KERB_ENCRYPTION_KEY(dd0, 0, &(val)->subkey)) return 0;
        if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    }
    MSASN1$ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000007) {
        (val)->o[0] |= 0x20;
        if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000007, &dd0, &di0)) return 0;
        if (!MSASN1$ASN1BERDecSXVal(dd0, 0x2, &(val)->sequence_number)) return 0;
        if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    }
    MSASN1$ASN1BERDecPeekTag(dd, &t);
    if (t == 0x80000008) {
        (val)->o[0] |= 0x10;
        if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000008, &dd0, &di0)) return 0;
        if (!ASN1Dec_PKERB_AUTHORIZATION_DATA(dd0, 0, &(val)->authorization_data)) return 0;
        if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    }
    if (!MSASN1$ASN1BERDecEndOfContents(pExplTagDec0, dd, di)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, pExplTagDec0, pbExplTagDataEnd0)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_CHECKSUM(ASN1decoding_t dec, ASN1uint32_t tag, KERB_CHECKSUM* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->checksum_type)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecOctetString(dd0, 0x4, &(val)->checksum)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd, di)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_ENCRYPTION_KEY(ASN1decoding_t dec, ASN1uint32_t tag, KERB_ENCRYPTION_KEY* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->keytype)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecOctetString(dd0, 0x4, &(val)->keyvalue)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd, di)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_PKERB_AUTHORIZATION_DATA(ASN1decoding_t dec, ASN1uint32_t tag,
                                                     PPKERB_AUTHORIZATION_DATA* val) {
    PPKERB_AUTHORIZATION_DATA* f;
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1uint32_t t;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di)) return 0;
    f = val;
    while (MSASN1$ASN1BERDecNotEndOfContents(dd, di)) {
        if (!MSASN1$ASN1BERDecPeekTag(dd, &t)) return 0;
        if (!(*f = (PPKERB_AUTHORIZATION_DATA)MSASN1$ASN1DecAlloc(dd, sizeof(**f)))) return 0;
        if (!ASN1Dec_PKERB_AUTHORIZATION_DATA_Seq(dd, 0, &(*f)->value)) return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd, di)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_PKERB_AUTHORIZATION_DATA_Seq(ASN1decoding_t dec, ASN1uint32_t tag,
                                                         PKERB_AUTHORIZATION_DATA_Seq* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x10, &dd, &di)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->auth_data_type)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecOctetString(dd0, 0x4, &(val)->auth_data)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd, di)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_CRED(ASN1decoding_t dec, ASN1uint32_t tag, KERB_CRED* val) {
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1decoding_t pExplTagDec0;
    ASN1octet_t* pbExplTagDataEnd0;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x40000016, &pExplTagDec0, &pbExplTagDataEnd0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(pExplTagDec0, 0x10, &dd, &di)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000000, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->version)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000001, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecS32Val(dd0, 0x2, &(val)->message_type)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!ASN1Dec_KERB_CRED_tickets(dd, 0, &(val)->tickets)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd, 0x80000003, &dd0, &di0)) return 0;
    if (!ASN1Dec_KERB_ENCRYPTED_DATA(dd0, 0, &(val)->encrypted_part)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dd, dd0, di0)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(pExplTagDec0, dd, di)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, pExplTagDec0, pbExplTagDataEnd0)) return 0;
    return 1;
}

static int ASN1CALL ASN1Dec_KERB_CRED_tickets(ASN1decoding_t dec, ASN1uint32_t tag, PKERB_CRED_tickets* val) {
    PKERB_CRED_tickets* f;
    ASN1decoding_t dd0;
    ASN1octet_t* di0;
    ASN1decoding_t dd;
    ASN1octet_t* di;
    ASN1uint32_t t;
    if (!MSASN1$ASN1BERDecExplicitTag(dec, tag ? tag : 0x80000002, &dd0, &di0)) return 0;
    if (!MSASN1$ASN1BERDecExplicitTag(dd0, 0x10, &dd, &di)) return 0;
    f = val;
    while (MSASN1$ASN1BERDecNotEndOfContents(dd, di)) {
        if (!MSASN1$ASN1BERDecPeekTag(dd, &t)) return 0;
        if (!(*f = (PKERB_CRED_tickets)MSASN1$ASN1DecAlloc(dd, sizeof(**f)))) return 0;
        if (!ASN1Dec_KERB_TICKET(dd, 0, &(*f)->value)) return 0;
        f = &(*f)->next;
    }
    *f = NULL;
    if (!MSASN1$ASN1BERDecEndOfContents(dd0, dd, di)) return 0;
    if (!MSASN1$ASN1BERDecEndOfContents(dec, dd0, di0)) return 0;
    return 1;
}

static void ASN1CALL ASN1Free_KERB_AP_REQUEST(KERB_AP_REQUEST* val) {
    if (val) {
        MSASN1$ASN1bitstring_free(&(val)->ap_options);
        ASN1Free_KERB_TICKET(&(val)->ticket);
        ASN1Free_KERB_ENCRYPTED_DATA(&(val)->authenticator);
    }
}

static void ASN1CALL ASN1Free_KERB_TICKET(KERB_TICKET* val) {
    if (val) {
        MSASN1$ASN1ztcharstring_free((val)->realm);
        ASN1Free_KERB_PRINCIPAL_NAME(&(val)->server_name);
        ASN1Free_KERB_ENCRYPTED_DATA(&(val)->encrypted_part);
        if ((val)->o[0] & 0x80) {
            ASN1Free_PKERB_TICKET_EXTENSIONS(&(val)->ticket_extensions);
        }
    }
}

static void ASN1CALL ASN1Free_KERB_ENCRYPTED_DATA(KERB_ENCRYPTED_DATA* val) {
    if (val) {
        MSASN1$ASN1octetstring_free(&(val)->cipher_text);
    }
}

static void ASN1CALL ASN1Free_KERB_PRINCIPAL_NAME(KERB_PRINCIPAL_NAME* val) {
    if (val) {
        ASN1Free_KERB_PRINCIPAL_NAME_name_string(&(val)->name_string);
    }
}

static void ASN1CALL ASN1Free_KERB_PRINCIPAL_NAME_name_string(PKERB_PRINCIPAL_NAME_name_string* val) {
    PKERB_PRINCIPAL_NAME_name_string f, ff;
    if (val) {
        for (f = *val; f; f = ff) {
            MSASN1$ASN1ztcharstring_free(f->value);
            ff = f->next;
            MSASN1$ASN1Free(f);
        }
    }
}

static void ASN1CALL ASN1Free_PKERB_TICKET_EXTENSIONS(PPKERB_TICKET_EXTENSIONS* val) {
    PPKERB_TICKET_EXTENSIONS f, ff;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_PKERB_TICKET_EXTENSIONS_Seq(&f->value);
            ff = f->next;
            MSASN1$ASN1Free(f);
        }
    }
}

static void ASN1CALL ASN1Free_PKERB_TICKET_EXTENSIONS_Seq(PKERB_TICKET_EXTENSIONS_Seq* val) {
    if (val) {
        MSASN1$ASN1octetstring_free(&(val)->te_data);
    }
}

static void ASN1CALL ASN1Free_KERB_AUTHENTICATOR(KERB_AUTHENTICATOR* val) {
    if (val) {
        MSASN1$ASN1ztcharstring_free((val)->client_realm);
        ASN1Free_KERB_PRINCIPAL_NAME(&(val)->client_name);
        if ((val)->o[0] & 0x80) {
            ASN1Free_KERB_CHECKSUM(&(val)->checksum);
        }
        if ((val)->o[0] & 0x40) {
            ASN1Free_KERB_ENCRYPTION_KEY(&(val)->subkey);
        }
        if ((val)->o[0] & 0x20) {
            MSASN1$ASN1intx_free(&(val)->sequence_number);
        }
        if ((val)->o[0] & 0x10) {
            ASN1Free_PKERB_AUTHORIZATION_DATA(&(val)->authorization_data);
        }
    }
}

static void ASN1CALL ASN1Free_PKERB_AUTHORIZATION_DATA_Seq(PKERB_AUTHORIZATION_DATA_Seq* val) {
    if (val) {
        MSASN1$ASN1octetstring_free(&(val)->auth_data);
    }
}

static void ASN1CALL ASN1Free_PKERB_AUTHORIZATION_DATA(PPKERB_AUTHORIZATION_DATA* val) {
    PPKERB_AUTHORIZATION_DATA f, ff;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_PKERB_AUTHORIZATION_DATA_Seq(&f->value);
            ff = f->next;
            MSASN1$ASN1Free(f);
        }
    }
}

static void ASN1CALL ASN1Free_KERB_CHECKSUM(KERB_CHECKSUM* val) {
    if (val) {
        MSASN1$ASN1octetstring_free(&(val)->checksum);
    }
}

static void ASN1CALL ASN1Free_KERB_REPLY_KEY_PACKAGE2(KERB_REPLY_KEY_PACKAGE2* val) {
    if (val) {
        ASN1Free_KERB_ENCRYPTION_KEY(&(val)->reply_key);
        if ((val)->o[0] & 0x80) {
            MSASN1$ASN1bitstring_free(&(val)->subject_public_key);
        }
    }
}

static void ASN1CALL ASN1Free_KERB_ENCRYPTION_KEY(KERB_ENCRYPTION_KEY* val) {
    if (val) {
        MSASN1$ASN1octetstring_free(&(val)->keyvalue);
    }
}

static void ASN1CALL ASN1Free_KERB_CRED(KERB_CRED* val) {
    if (val) {
        ASN1Free_KERB_CRED_tickets(&(val)->tickets);
        ASN1Free_KERB_ENCRYPTED_DATA(&(val)->encrypted_part);
    }
}

static void ASN1CALL ASN1Free_KERB_CRED_tickets(PKERB_CRED_tickets* val) {
    PKERB_CRED_tickets f, ff;
    if (val) {
        for (f = *val; f; f = ff) {
            ASN1Free_KERB_TICKET(&f->value);
            ff = f->next;
            MSASN1$ASN1Free(f);
        }
    }
}