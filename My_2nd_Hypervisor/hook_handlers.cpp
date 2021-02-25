#include "hook_handler.h"
#include "npt_hook.h"

typedef NTSTATUS (NTAPI *NtQueryInfoFile)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation,
	ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);

NPTHOOK_ENTRY* NtQueryInfoFilehk_Entry = 0;

NTSTATUS NTAPI NtQueryInfoFile_handler(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, 
	ULONG Length, FILE_INFORMATION_CLASS FileInformationClass)
{
	/*	call original function	*/
	NTSTATUS status = reinterpret_cast<NtQueryInfoFile>(&NtQueryInfoFilehk_Entry->Jmpout)(FileHandle, 
		IoStatusBlock, FileInformation, Length, FileInformationClass);

	DbgPrint("===========================================================================================================================\n");

	DbgPrint("[HOOK]  NtQueryInformationFile hook called ! \n");

	DbgPrint("[HOOK]  FileHandle: %p	IoStatusBlock: %p	FileInformation: %p	Length: %i	FileInformationClass: %i	\n",
		FileHandle, IoStatusBlock, FileInformation, Length, FileInformationClass);

	DbgPrint("[HOOK]  NtQueryInformationFile status:	%p \n", status);

	return status;
}