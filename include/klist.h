#pragma once

#include <windows.h>
#include <ntsecapi.h>
#include "base64.h"
#include "common.h"
#include "sessions.h"

void execute_klist(WCHAR** dispatch, HANDLE hToken, LUID luid, BOOL currentLuid, BOOL dump);
void EnumerateTickets(LUID*, BOOL, HANDLE);
NTSTATUS ExtractTicket(HANDLE hLsa, ULONG authPackage, LUID luid, UNICODE_STRING targetName, PUCHAR* ticket,
                       PULONG ticketSize);
void PrintTicketInfo(WCHAR** dispatch, KERB_TICKET_CACHE_INFO_EX cacheInfo);
void PrintTicketFlags(WCHAR** dispatch, ULONG ticketFlags);
