#pragma once
#include "Utils.h"

extern NPTHOOK_ENTRY*	NtQueryInfoFilehk_Entry;
NTSTATUS NTAPI NtQueryInfoFile_handler(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
	ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);