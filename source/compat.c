#include <windows.h>
#include "bofdefs.h"

// From TrustedSec's CS-Situational-Awareness-BOF
typedef struct LoadedLibrary
{
    HMODULE hMod;
    const char *name;
} LoadedLibrary, *PLoadedLibrary;
LoadedLibrary loadedLibraries[2] __attribute__((section(".data"))) = {0};
DWORD loadedLibrariesCount __attribute__((section(".data"))) = 0;

FARPROC DynamicLoad(const char *library, const char *function)
{
    FARPROC fp = NULL;
    HMODULE hMod = NULL;
    DWORD i = 0;
    DWORD liblen = 0;
    for (i = 0; i < loadedLibrariesCount; i++)
    {
        if (_strcmp(library, loadedLibraries[i].name) == 0)
        {
            hMod = loadedLibraries[i].hMod;
        }
    }
    if (!hMod)
    {
        hMod = LoadLibraryA(library);
        if (!hMod)
        {
            PRINT(NULL, "[!] Could not find library %s to load.\n", library);
            return NULL;
        }
        loadedLibraries[loadedLibrariesCount].hMod = hMod;
        loadedLibraries[loadedLibrariesCount].name = library;
        loadedLibrariesCount++;
    }
    fp = GetProcAddress(hMod, function);

    if (NULL == fp)
    {
        PRINT(NULL, "[!] Could not find function %s.\n", function);
    }
    return fp;
}

// secur32
typedef NTSTATUS(WINAPI *_LsaGetLogonSessionData)(PLUID LogonId, PSECURITY_LOGON_SESSION_DATA *ppLogonSessionData);
typedef NTSTATUS(WINAPI *_LsaFreeReturnBuffer)(PVOID Buffer);
typedef NTSTATUS(WINAPI *_LsaEnumerateLogonSessions)(PULONG LogonSessionCount, PLUID *LogonSessionList);
typedef NTSTATUS(WINAPI *_LsaRegisterLogonProcess)(PLSA_STRING LogonProcessName, PHANDLE LsaHandle, PLSA_OPERATIONAL_MODE SecurityMode);
typedef NTSTATUS(WINAPI *_LsaLookupAuthenticationPackage)(HANDLE LsaHandle, PLSA_STRING PackageName, PULONG AuthenticationPackage);
typedef NTSTATUS(WINAPI *_LsaCallAuthenticationPackage)(HANDLE LsaHandle, ULONG AuthenticationPackage,
                                                        PVOID ProtocolSubmitBuffer, ULONG SubmitBufferLength,
                                                        PVOID *ProtocolReturnBuffer, PULONG ReturnBufferLength,
                                                        PNTSTATUS ProtocolStatus);
typedef NTSTATUS(WINAPI *_LsaDeregisterLogonProcess)(HANDLE LsaHandle);
typedef NTSTATUS(WINAPI *_LsaConnectUntrusted)(PHANDLE LsaHandle);
typedef SECURITY_STATUS(WINAPI *_AcquireCredentialsHandleA)(SEC_CHAR *pszPrincipal, SEC_CHAR *pszPackage,
                                                            unsigned __LONG32 fCredentialUse, void *pvLogonId,
                                                            void *pAuthData, SEC_GET_KEY_FN pGetKeyFn,
                                                            void *pvGetKeyArgument, PCredHandle phCredential,
                                                            PTimeStamp ptsExpiry);
typedef SECURITY_STATUS(WINAPI *_InitializeSecurityContextA)(
    PCredHandle phCredential, PCtxtHandle phContext, SEC_CHAR *pszTargetName, unsigned __LONG32 fContextReq,
    unsigned __LONG32 Reserved1, unsigned __LONG32 TargetDataRep, PSecBufferDesc pInput, unsigned __LONG32 Reserved2,
    PCtxtHandle phNewContext, PSecBufferDesc pOutput, unsigned __LONG32 *pfContextAttr, PTimeStamp ptsExpiry);
typedef SECURITY_STATUS(WINAPI *_FreeContextBuffer)(void *pvContextBuffer);
typedef SECURITY_STATUS(WINAPI *_DeleteSecurityContext)(PCtxtHandle phContext);
typedef SECURITY_STATUS(WINAPI *_FreeCredentialsHandle)(PCredHandle phCredential);

#define SECUR32$LsaGetLogonSessionData ((_LsaGetLogonSessionData)DynamicLoad("SECUR32", "LsaGetLogonSessionData"))
#define SECUR32$LsaFreeReturnBuffer ((_LsaFreeReturnBuffer)DynamicLoad("SECUR32", "LsaFreeReturnBuffer"))
#define SECUR32$LsaEnumerateLogonSessions ((_LsaEnumerateLogonSessions)DynamicLoad("SECUR32", "LsaEnumerateLogonSessions"))
#define SECUR32$LsaRegisterLogonProcess ((_LsaRegisterLogonProcess)DynamicLoad("SECUR32", "LsaRegisterLogonProcess"))
#define SECUR32$LsaLookupAuthenticationPackage ((_LsaLookupAuthenticationPackage)DynamicLoad("SECUR32", "LsaLookupAuthenticationPackage"))
#define SECUR32$LsaCallAuthenticationPackage ((_LsaCallAuthenticationPackage)DynamicLoad("SECUR32", "LsaCallAuthenticationPackage"))
#define SECUR32$LsaDeregisterLogonProcess ((_LsaDeregisterLogonProcess)DynamicLoad("SECUR32", "LsaDeregisterLogonProcess"))
#define SECUR32$LsaConnectUntrusted ((_LsaConnectUntrusted)DynamicLoad("SECUR32", "LsaConnectUntrusted"))
#define SECUR32$AcquireCredentialsHandleA ((_AcquireCredentialsHandleA)DynamicLoad("SECUR32", "AcquireCredentialsHandleA"))
#define SECUR32$InitializeSecurityContextA ((_InitializeSecurityContextA)DynamicLoad("SECUR32", "InitializeSecurityContextA"))
#define SECUR32$FreeContextBuffer ((_FreeContextBuffer)DynamicLoad("SECUR32", "FreeContextBuffer"))
#define SECUR32$DeleteSecurityContext ((_DeleteSecurityContext)DynamicLoad("SECUR32", "DeleteSecurityContext"))
#define SECUR32$FreeCredentialsHandle ((_FreeCredentialsHandle)DynamicLoad("SECUR32", "FreeCredentialsHandle"))

// msasn1
typedef ASN1module_t(ASN1API *_ASN1_CreateModule)(ASN1uint32_t nVersion, ASN1encodingrule_e eRule, ASN1uint32_t dwFlags,
                                                  ASN1uint32_t cPDU, const ASN1GenericFun_t apfnEncoder[],
                                                  const ASN1GenericFun_t apfnDecoder[],
                                                  const ASN1FreeFun_t apfnFreeMemory[], const ASN1uint32_t acbStructSize[],
                                                  ASN1magic_t nModuleName);
typedef void(ASN1API *_ASN1_CloseModule)(ASN1module_t pModule);
typedef ASN1error_e(ASN1API *_ASN1_CreateEncoder)(ASN1module_t pModule, ASN1encoding_t *ppEncoderInfo, ASN1octet_t *pbBuf,
                                                  ASN1uint32_t cbBufSize, ASN1encoding_t pParent);
typedef ASN1error_e(ASN1API *_ASN1_Encode)(ASN1encoding_t pEncoderInfo, void *pDataStruct, ASN1uint32_t nPduNum,
                                           ASN1uint32_t dwFlags, ASN1octet_t *pbBuf, ASN1uint32_t cbBufSize);
typedef void(ASN1API *_ASN1_CloseEncoder)(ASN1encoding_t pEncoderInfo);
typedef void(ASN1API *_ASN1_FreeEncoded)(ASN1encoding_t pEncoderInfo, void *pBuf);
typedef ASN1error_e(ASN1API *_ASN1_CreateDecoder)(ASN1module_t pModule, ASN1decoding_t *ppDecoderInfo, ASN1octet_t *pbBuf,
                                                  ASN1uint32_t cbBufSize, ASN1decoding_t pParent);
typedef ASN1error_e(ASN1API *_ASN1_Decode)(ASN1decoding_t pDecoderInfo, void **ppDataStruct, ASN1uint32_t nPduNum,
                                           ASN1uint32_t dwFlags, ASN1octet_t *pbBuf, ASN1uint32_t cbBufSize);
typedef void(ASN1API *_ASN1_CloseDecoder)(ASN1decoding_t pDecoderInfo);
typedef void(ASN1API *_ASN1_FreeDecoded)(ASN1decoding_t pDecoderInfo, void *pDataStruct, ASN1uint32_t nPduNum);
typedef void(ASN1API *_ASN1bitstring_free)(ASN1bitstring_t *);
typedef void(ASN1API *_ASN1ztcharstring_free)(ASN1ztcharstring_t);
typedef void(ASN1API *_ASN1octetstring_free)(ASN1octetstring_t *);
typedef void(ASN1API *_ASN1intx_free)(ASN1intx_t *);
typedef int(ASN1API *_ASN1BERDecExplicitTag)(ASN1decoding_t dec, ASN1uint32_t tag, ASN1decoding_t *dd, ASN1octet_t **di);
typedef int(ASN1API *_ASN1BERDecS32Val)(ASN1decoding_t dec, ASN1uint32_t tag, ASN1int32_t *);
typedef int(ASN1API *_ASN1BERDecEndOfContents)(ASN1decoding_t dec, ASN1decoding_t dd, ASN1octet_t *di);
typedef int(ASN1API *_ASN1BERDecBitString)(ASN1decoding_t dec, ASN1uint32_t tag, ASN1bitstring_t *);
typedef int(ASN1API *_ASN1BERDecZeroCharString)(ASN1decoding_t dec, ASN1uint32_t tag, ASN1ztcharstring_t *);
typedef int(ASN1API *_ASN1BERDecPeekTag)(ASN1decoding_t dec, ASN1uint32_t *tag);
typedef int(ASN1API *_ASN1BERDecOctetString)(ASN1decoding_t dec, ASN1uint32_t tag, ASN1octetstring_t *val);
typedef int(ASN1API *_ASN1BERDecNotEndOfContents)(ASN1decoding_t dec, ASN1octet_t *di);
typedef void *(ASN1API *_ASN1DecAlloc)(ASN1decoding_t dec, ASN1uint32_t size);
typedef void *(ASN1API *_ASN1DecRealloc)(ASN1decoding_t dec, void *ptr, ASN1uint32_t size);
typedef void(ASN1API *_ASN1Free)(void *ptr);
typedef int(ASN1API *_ASN1BERDecGeneralizedTime)(ASN1decoding_t dec, ASN1uint32_t tag, ASN1generalizedtime_t *);
typedef int(ASN1API *_ASN1BERDecSXVal)(ASN1decoding_t dec, ASN1uint32_t tag, ASN1intx_t *);
typedef int(ASN1API *_ASN1BEREncExplicitTag)(ASN1encoding_t enc, ASN1uint32_t tag, ASN1uint32_t *pLengthOffset);
typedef int(ASN1API *_ASN1BEREncS32)(ASN1encoding_t enc, ASN1uint32_t tag, ASN1int32_t);
typedef int(ASN1API *_ASN1BEREncEndOfContents)(ASN1encoding_t enc, ASN1uint32_t LengthOffset);
typedef int(ASN1API *_ASN1DEREncCharString)(ASN1encoding_t enc, ASN1uint32_t tag, ASN1uint32_t len, ASN1char_t *val);
typedef int(ASN1API *_ASN1DEREncOctetString)(ASN1encoding_t enc, ASN1uint32_t tag, ASN1uint32_t len, ASN1octet_t *val);

#define MSASN1$ASN1_CreateModule ((_ASN1_CreateModule)DynamicLoad("MSASN1", "ASN1_CreateModule"))
#define MSASN1$ASN1_CloseModule ((_ASN1_CloseModule)DynamicLoad("MSASN1", "ASN1_CloseModule"))
#define MSASN1$ASN1_CreateEncoder ((_ASN1_CreateEncoder)DynamicLoad("MSASN1", "ASN1_CreateEncoder"))
#define MSASN1$ASN1_Encode ((_ASN1_Encode)DynamicLoad("MSASN1", "ASN1_Encode"))
#define MSASN1$ASN1_CloseEncoder ((_ASN1_CloseEncoder)DynamicLoad("MSASN1", "ASN1_CloseEncoder"))
#define MSASN1$ASN1_FreeEncoded ((_ASN1_FreeEncoded)DynamicLoad("MSASN1", "ASN1_FreeEncoded"))
#define MSASN1$ASN1_CreateDecoder ((_ASN1_CreateDecoder)DynamicLoad("MSASN1", "ASN1_CreateDecoder"))
#define MSASN1$ASN1_Decode ((_ASN1_Decode)DynamicLoad("MSASN1", "ASN1_Decode"))
#define MSASN1$ASN1_CloseDecoder ((_ASN1_CloseDecoder)DynamicLoad("MSASN1", "ASN1_CloseDecoder"))
#define MSASN1$ASN1_FreeDecoded ((_ASN1_FreeDecoded)DynamicLoad("MSASN1", "ASN1_FreeDecoded"))
#define MSASN1$ASN1bitstring_free ((_ASN1bitstring_free)DynamicLoad("MSASN1", "ASN1bitstring_free"))
#define MSASN1$ASN1ztcharstring_free ((_ASN1ztcharstring_free)DynamicLoad("MSASN1", "ASN1ztcharstring_free"))
#define MSASN1$ASN1octetstring_free ((_ASN1octetstring_free)DynamicLoad("MSASN1", "ASN1octetstring_free"))
#define MSASN1$ASN1intx_free ((_ASN1intx_free)DynamicLoad("MSASN1", "ASN1intx_free"))
#define MSASN1$ASN1BERDecExplicitTag ((_ASN1BERDecExplicitTag)DynamicLoad("MSASN1", "ASN1BERDecExplicitTag"))
#define MSASN1$ASN1BERDecS32Val ((_ASN1BERDecS32Val)DynamicLoad("MSASN1", "ASN1BERDecS32Val"))
#define MSASN1$ASN1BERDecEndOfContents ((_ASN1BERDecEndOfContents)DynamicLoad("MSASN1", "ASN1BERDecEndOfContents"))
#define MSASN1$ASN1BERDecBitString ((_ASN1BERDecBitString)DynamicLoad("MSASN1", "ASN1BERDecBitString"))
#define MSASN1$ASN1BERDecZeroCharString ((_ASN1BERDecZeroCharString)DynamicLoad("MSASN1", "ASN1BERDecZeroCharString"))
#define MSASN1$ASN1BERDecPeekTag ((_ASN1BERDecPeekTag)DynamicLoad("MSASN1", "ASN1BERDecPeekTag"))
#define MSASN1$ASN1BERDecOctetString ((_ASN1BERDecOctetString)DynamicLoad("MSASN1", "ASN1BERDecOctetString"))
#define MSASN1$ASN1BERDecNotEndOfContents ((_ASN1BERDecNotEndOfContents)DynamicLoad("MSASN1", "ASN1BERDecNotEndOfContents"))
#define MSASN1$ASN1DecAlloc ((_ASN1DecAlloc)DynamicLoad("MSASN1", "ASN1DecAlloc"))
#define MSASN1$ASN1DecRealloc ((_ASN1DecRealloc)DynamicLoad("MSASN1", "ASN1DecRealloc"))
#define MSASN1$ASN1Free ((_ASN1Free)DynamicLoad("MSASN1", "ASN1Free"))
#define MSASN1$ASN1BERDecGeneralizedTime ((_ASN1BERDecGeneralizedTime)DynamicLoad("MSASN1", "ASN1BERDecGeneralizedTime"))
#define MSASN1$ASN1BERDecSXVal ((_ASN1BERDecSXVal)DynamicLoad("MSASN1", "ASN1BERDecSXVal"))
#define MSASN1$ASN1BEREncExplicitTag ((_ASN1BEREncExplicitTag)DynamicLoad("MSASN1", "ASN1BEREncExplicitTag"))
#define MSASN1$ASN1BEREncS32 ((_ASN1BEREncS32)DynamicLoad("MSASN1", "ASN1BEREncS32"))
#define MSASN1$ASN1DEREncCharString ((_ASN1DEREncCharString)DynamicLoad("MSASN1", "ASN1DEREncCharString"))
#define MSASN1$ASN1DEREncOctetString ((_ASN1DEREncOctetString)DynamicLoad("MSASN1", "ASN1DEREncOctetString"))
#define MSASN1$ASN1BEREncEndOfContents ((_ASN1BEREncEndOfContents)DynamicLoad("MSASN1", "ASN1BEREncEndOfContents"))