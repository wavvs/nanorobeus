#pragma once
/* data API */
#include <windows.h>
#ifdef BOF
typedef struct {
    char *original; /* the original buffer [so we can free it] */
    char *buffer;   /* current pointer into our buffer */
    int length;     /* remaining length of data */
    int size;       /* total size of this buffer */
} datap;

DECLSPEC_IMPORT void BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int BeaconDataInt(datap *parser);
DECLSPEC_IMPORT short BeaconDataShort(datap *parser);
DECLSPEC_IMPORT int BeaconDataLength(datap *parser);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);

/* format API */
typedef struct {
    char *original; /* the original buffer [so we can free it] */
    char *buffer;   /* current pointer into our buffer */
    int length;     /* remaining length of data */
    int size;       /* total size of this buffer */
} formatp;

DECLSPEC_IMPORT void BeaconFormatAlloc(formatp *format, int maxsz);
DECLSPEC_IMPORT void BeaconFormatReset(formatp *format);
DECLSPEC_IMPORT void BeaconFormatFree(formatp *format);
DECLSPEC_IMPORT void BeaconFormatAppend(formatp *format, char *text, int len);
DECLSPEC_IMPORT void BeaconFormatPrintf(formatp *format, char *fmt, ...);
DECLSPEC_IMPORT char *BeaconFormatToString(formatp *format, int *size);
DECLSPEC_IMPORT void BeaconFormatInt(formatp *format, int value);

/* Output Functions */
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_OUTPUT_OEM 0x1e
#define CALLBACK_ERROR 0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

DECLSPEC_IMPORT void BeaconPrintf(int type, char *fmt, ...);
DECLSPEC_IMPORT void BeaconOutput(int type, char *data, int len);

/* Token Functions */
DECLSPEC_IMPORT BOOL BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT void BeaconRevertToken();
DECLSPEC_IMPORT BOOL BeaconIsAdmin();

/* Spawn+Inject Functions */
DECLSPEC_IMPORT void BeaconGetSpawnTo(BOOL x86, char *buffer, int length);
DECLSPEC_IMPORT void BeaconInjectProcess(HANDLE hProc, int pid, char *payload, int p_len, int p_offset, char *arg,
                                         int a_len);
DECLSPEC_IMPORT void BeaconInjectTemporaryProcess(PROCESS_INFORMATION *pInfo, char *payload, int p_len, int p_offset,
                                                  char *arg, int a_len);
DECLSPEC_IMPORT void BeaconCleanupProcess(PROCESS_INFORMATION *pInfo);

/* Utility Functions */
DECLSPEC_IMPORT BOOL toWideChar(char *src, wchar_t *dst, int max);

#define PRINT(dispatch, ...) \
    { BeaconPrintf(CALLBACK_OUTPUT, __VA_ARGS__); }
#elif BRC4
DECLSPEC_IMPORT int BadgerDispatch(WCHAR **dispatch, const char *__format, ...);
DECLSPEC_IMPORT int BadgerDispatchW(WCHAR **dispatch, const WCHAR *__format, ...);
DECLSPEC_IMPORT size_t BadgerStrlen(CHAR *buf);
DECLSPEC_IMPORT size_t BadgerWcslen(WCHAR *buf);

DECLSPEC_IMPORT void *BadgerMemcpy(void *dest, const void *src, size_t len);
DECLSPEC_IMPORT void *BadgerMemset(void *dest, int val, size_t len);

DECLSPEC_IMPORT int BadgerStrcmp(const char *p1, const char *p2);
DECLSPEC_IMPORT int BadgerWcscmp(const wchar_t *s1, const wchar_t *s2);
DECLSPEC_IMPORT int BadgerAtoi(char *string);

#define PRINT(dispatch, ...) \
    { BadgerDispatch(dispatch, __VA_ARGS__); }
#else

#define PRINT(dispatch, ...) \
    { fprintf(stdout, __VA_ARGS__); }

#endif
