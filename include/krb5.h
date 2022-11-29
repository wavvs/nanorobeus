#pragma once

#include "msasn1.h"

// Copyright (c) Microsoft Corporation

#define KRB_KEY_USAGE_AP_REQ_AUTHENTICATOR 11
#define KRB_KEY_USAGE_KRB_CRED_ENCRYPTED_PART 14

#define version_present 0x80
#define ticket_extensions_present 0x80
#define checksum_present 0x80
#define KERB_AUTHENTICATOR_subkey_present 0x40
#define KERB_AUTHENTICATOR_sequence_number_present 0x20
#define KERB_AUTHENTICATOR_authorization_data_present 0x10
#define subject_public_key_present 0x80

#define KERB_ENCRYPTED_DATA_PDU 6
#define KERB_ENCRYPTION_KEY_PDU 7
#define KERB_CHECKSUM_PDU 8
#define KERB_REPLY_KEY_PACKAGE2_PDU 15
#define KERB_TICKET_PDU 28
#define KERB_AUTHENTICATOR_PDU 30
#define KERB_AP_REQUEST_PDU 31
#define KERB_CRED_PDU 36

#define SIZE_KRB5_Module_PDU_6 sizeof(KERB_ENCRYPTED_DATA)
#define SIZE_KRB5_Module_PDU_7 sizeof(KERB_ENCRYPTION_KEY)
#define SIZE_KRB5_Module_PDU_8 sizeof(KERB_CHECKSUM)
#define SIZE_KRB5_Module_PDU_15 sizeof(KERB_REPLY_KEY_PACKAGE2)
#define SIZE_KRB5_Module_PDU_28 sizeof(KERB_TICKET)
#define SIZE_KRB5_Module_PDU_30 sizeof(KERB_AUTHENTICATOR)
#define SIZE_KRB5_Module_PDU_31 sizeof(KERB_AP_REQUEST)
#define SIZE_KRB5_Module_PDU_36 sizeof(KERB_CRED)

typedef LONG KERBERR, *PKERBERR;
#define KDC_ERR_NONE ((KERBERR)0x0)
#define KRB_ERR_GENERIC ((KERBERR)0x3C)
#define KDC_ERR_MORE_DATA ((KERBERR)0x80000001)
#define KERB_SUCCESS(_kerberr_) ((KERBERR)(_kerberr_) == KDC_ERR_NONE)

typedef struct _KERB_GSS_CHECKSUM {
    ULONG BindLength;
    ULONG BindHash[4];
    ULONG GssFlags;
    USHORT Delegation;
    USHORT DelegationLength;
    UCHAR DelegationInfo[ANYSIZE_ARRAY];
} KERB_GSS_CHECKSUM, *PKERB_GSS_CHECKSUM;

typedef ASN1ztcharstring_t KERB_PRINCIPAL_NAME_name_string_Seq;
typedef struct KERB_PRINCIPAL_NAME_name_string_s* PKERB_PRINCIPAL_NAME_name_string;
typedef struct KERB_PRINCIPAL_NAME_name_string_s {
    PKERB_PRINCIPAL_NAME_name_string next;
    KERB_PRINCIPAL_NAME_name_string_Seq value;
} KERB_PRINCIPAL_NAME_name_string_Element, *KERB_PRINCIPAL_NAME_name_string;

typedef struct PKERB_TICKET_EXTENSIONS_s* PPKERB_TICKET_EXTENSIONS;
typedef struct PKERB_TICKET_EXTENSIONS_Seq {
    ASN1int32_t te_type;
    ASN1octetstring_t te_data;
} PKERB_TICKET_EXTENSIONS_Seq;
typedef struct PKERB_TICKET_EXTENSIONS_s {
    PPKERB_TICKET_EXTENSIONS next;
    PKERB_TICKET_EXTENSIONS_Seq value;
} PKERB_TICKET_EXTENSIONS_Element, *PKERB_TICKET_EXTENSIONS;

typedef ASN1bitstring_t KERB_AP_OPTIONS;
typedef ASN1ztcharstring_t KERB_REALM;
typedef ASN1generalizedtime_t KERB_TIME;
typedef ASN1intx_t KERB_SEQUENCE_NUMBER_LARGE;

typedef struct PKERB_AUTHORIZATION_DATA_Seq {
    ASN1int32_t auth_data_type;
    ASN1octetstring_t auth_data;
} PKERB_AUTHORIZATION_DATA_Seq;

typedef struct PKERB_AUTHORIZATION_DATA_s* PPKERB_AUTHORIZATION_DATA;
typedef struct PKERB_AUTHORIZATION_DATA_s {
    PPKERB_AUTHORIZATION_DATA next;
    PKERB_AUTHORIZATION_DATA_Seq value;
} PKERB_AUTHORIZATION_DATA_Element, *PKERB_AUTHORIZATION_DATA;

typedef struct KERB_PRINCIPAL_NAME {
    ASN1int32_t name_type;
    PKERB_PRINCIPAL_NAME_name_string name_string;
} KERB_PRINCIPAL_NAME;

typedef struct KERB_ENCRYPTED_DATA {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1int32_t encryption_type;
    ASN1int32_t version;
    ASN1octetstring_t cipher_text;
} KERB_ENCRYPTED_DATA;

typedef struct KERB_ENCRYPTION_KEY {
    ASN1int32_t keytype;
    ASN1octetstring_t keyvalue;
} KERB_ENCRYPTION_KEY;

typedef struct KERB_CHECKSUM {
    ASN1int32_t checksum_type;
    ASN1octetstring_t checksum;
} KERB_CHECKSUM;

typedef struct KERB_REPLY_KEY_PACKAGE2 {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    KERB_ENCRYPTION_KEY reply_key;
    ASN1int32_t nonce;
    ASN1bitstring_t subject_public_key;
} KERB_REPLY_KEY_PACKAGE2;

typedef struct KERB_TICKET {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1int32_t ticket_version;
    KERB_REALM realm;
    KERB_PRINCIPAL_NAME server_name;
    KERB_ENCRYPTED_DATA encrypted_part;
    PPKERB_TICKET_EXTENSIONS ticket_extensions;
} KERB_TICKET;

typedef struct KERB_AUTHENTICATOR {
    union {
        ASN1uint16_t bit_mask;
        ASN1octet_t o[1];
    };
    ASN1int32_t authenticator_version;
    KERB_REALM client_realm;
    KERB_PRINCIPAL_NAME client_name;
    KERB_CHECKSUM checksum;
    ASN1int32_t client_usec;
    KERB_TIME client_time;
    KERB_ENCRYPTION_KEY subkey;
    KERB_SEQUENCE_NUMBER_LARGE sequence_number;
    PPKERB_AUTHORIZATION_DATA authorization_data;
} KERB_AUTHENTICATOR;

typedef struct KERB_AP_REQUEST {
    ASN1int32_t version;
    ASN1int32_t message_type;
    KERB_AP_OPTIONS ap_options;
    KERB_TICKET ticket;
    KERB_ENCRYPTED_DATA authenticator;
} KERB_AP_REQUEST, *PKERB_AP_REQUEST;

typedef struct KERB_CRED_tickets_s* PKERB_CRED_tickets;
typedef struct KERB_CRED_tickets_s {
    PKERB_CRED_tickets next;
    KERB_TICKET value;
} KERB_CRED_tickets_Element, *KERB_CRED_tickets;
typedef struct KERB_CRED {
    ASN1int32_t version;
    ASN1int32_t message_type;
    PKERB_CRED_tickets tickets;
    KERB_ENCRYPTED_DATA encrypted_part;
} KERB_CRED;

ASN1module_t ASN1CALL KRB5_Module_Startup(void);
void ASN1CALL KRB5_Module_Cleanup(ASN1module_t module);
KERBERR KerbInitAsn(ASN1module_t module, ASN1encoding_t* pEnc, ASN1decoding_t* pDec);
void KerbTermAsn(ASN1encoding_t pEnc, ASN1decoding_t pDec);
KERBERR NTAPI KerbUnpackData(ASN1module_t module, PUCHAR Data, ULONG DataSize, ULONG PduValue, PVOID* DecodedData);
KERBERR NTAPI KerbPackData(ASN1module_t module, PVOID Data, ULONG PduValue, PULONG DataSize, PUCHAR* EncodedData);
void KerbFreeData(ASN1module_t module, ULONG PduValue, PVOID Data);