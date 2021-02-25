#include	"npt_hook.h"
#include	"hook_handler.h"

#define    DIFFERENCE(a, b)    max(a,b) - min(a, b)

NPTHOOK_ENTRY* GetHookByPhysicalPage(HYPERVISOR_DATA* HvData, UINT64 PagePhysical)
{
	PFN_NUMBER pfn = PagePhysical >> PAGE_SHIFT;

	NPTHOOK_ENTRY* nptHook;

	for (LIST_ENTRY* entry = HvData->HookListHead; MmIsAddressValid(entry); entry = entry->Flink) 
	{
		nptHook = CONTAINING_RECORD(entry, NPTHOOK_ENTRY, HookList);

		if (nptHook->NptEntry1) {

            if (nptHook->NptEntry1->PageFrameNumber == pfn) {
				return nptHook;
            }
        }
	}

	return 0;
}




NPTHOOK_ENTRY* GetHookByOldFuncAddress(HYPERVISOR_DATA* HvData, PVOID	FuncAddr)
{
	NPTHOOK_ENTRY* nptHook;

	for (LIST_ENTRY* entry = HvData->HookListHead; MmIsAddressValid(entry); entry = entry->Flink)
	{
		nptHook = CONTAINING_RECORD(entry, NPTHOOK_ENTRY, HookList);

		if (DIFFERENCE((ULONG64)nptHook->Jmpout.OriginalFunc, ((ULONG64)FuncAddr)) < 30)
		{
			return nptHook;
		}
	}

	return 0;
}




void	SetAllPagesExecute(VPROCESSOR_DATA* VpData, bool execute, PDPTE_64* SingledOutPdpte,
	PDE_64* SingledOutPde, PTE_64* SingledOutPte)
{
	PHYSICAL_ADDRESS	Pml4Base;
	Pml4Base.QuadPart = VpData->GuestVmcb.ControlArea.NCr3;

	PML4E_64* Pml4 = (PML4E_64*)MmGetVirtualForPhysical(Pml4Base);


	PDPTE_64* Pdpte = (PDPTE_64*)Utils::GetVaFromPfn(Pml4[0].PageFrameNumber);

	/*	Set All Pdpte to permission		*/
	for (int i = 0; i < 512; ++i)
	{
		Pdpte[i].ExecuteDisable = !execute;
	}
	SingledOutPdpte->ExecuteDisable = execute;


	PDE_64* Pde = (PDE_64*)Utils::GetVaFromPfn(SingledOutPdpte->PageFrameNumber);

	for (int i = 0; i < 512; ++i)
	{
		Pde[i].ExecuteDisable = !execute;
	}
	SingledOutPde->ExecuteDisable = execute;


	PTE_64* Pte = (PTE_64*)Utils::GetVaFromPfn(SingledOutPde->PageFrameNumber);

	for (int i = 0; i < 512; ++i)
	{
		Pte[i].ExecuteDisable = !execute;
	}
	SingledOutPte->ExecuteDisable = execute;
}




int PageOffset;
NPTHOOK_ENTRY* AddHookedPage(HYPERVISOR_DATA* HvData, PVOID PhysicalAddr, char* patch, int PatchLen)
{
	PageOffset = (ULONG64)PhysicalAddr & (PAGE_SIZE - 1);

	PT_ENTRY_64* InnocentNptEntry = Utils::GetPte(PhysicalAddr, HvData->PrimaryNCr3);
	PT_ENTRY_64* HookedNptEntry = Utils::GetPte(PhysicalAddr, HvData->SecondaryNCr3);

	///CopyPage = (ULONG64)ExAllocatePool(NonPagedPool, PAGE_SIZE);

	ULONG64	PageAddr = (ULONG64)Utils::GetVaFromPfn(InnocentNptEntry->PageFrameNumber);

	///DbgPrint("[SETUP] NptEntry page frame number %p \n", NptEntry->PageFrameNumber);
	///DbgPrint("[SETUP] Hook placed at physical address %p \n", PhysicalAddr);

	memcpy((PVOID)CopyPage, (PVOID)PageAddr, PAGE_SIZE);
	memcpy((PVOID)(CopyPage + PageOffset), patch, PatchLen);

	DbgPrint("CopyPage %p + PageOffset %p \n", CopyPage, PageOffset);


	DbgPrint("original page bytes: ");
	for (int i = 0; i < 15; ++i)
	{
		DbgPrint(" %02x ", (UCHAR)((UCHAR*)PageAddr + PageOffset)[i]);
	}
	DbgPrint("\n");

	DbgPrint("InnocentNptEntry pageframenumber %p\n", InnocentNptEntry->PageFrameNumber);
	DbgPrint("HookedNptEntry pageframenumber %p\n", HookedNptEntry->PageFrameNumber);

	InnocentNptEntry->ExecuteDisable = 1;
	HookedNptEntry->ExecuteDisable = 0;
	HookedNptEntry->PageFrameNumber = Utils::GetPfnFromVa(CopyPage);

	LIST_ENTRY* entry = HvData->HookListHead;

	while (MmIsAddressValid(entry->Flink))
	{
		entry = entry->Flink;
    }

	NPTHOOK_ENTRY* NewHook = (NPTHOOK_ENTRY*)ExAllocatePoolZero(NonPagedPool, sizeof(NPTHOOK_ENTRY), 'Kooh');

	entry->Flink = &NewHook->HookList;


	/*	save original bytes		*/
	memset(&NewHook->Shellcode, '\x90', 64);
	memcpy(&NewHook->Jmpout.OriginalBytes, (PVOID)(PageAddr + PageOffset), PatchLen);

	NewHook->NptEntry1 = InnocentNptEntry;
	NewHook->NptEntry2 = HookedNptEntry;

	return	NewHook;
}



void SetHooks(HYPERVISOR_DATA* HvData)
{
	/*	NPT hook NtQueryInformationFile	*/

	UNICODE_STRING	QueryInfoFileName = RTL_CONSTANT_STRING(L"NtQueryInformationFile");
	PVOID	QueryInfoFile = MmGetSystemRoutineAddress(&QueryInfoFileName);
	DbgPrint("ntqueryinformationfile address %p\n", QueryInfoFile);

	PVOID	QueryInfoFilePa = (PVOID)MmGetPhysicalAddress(QueryInfoFile).QuadPart;

	char	Jmp[15];

	Utils::GetJmpCode((ULONG64)NtQueryInfoFile_handler, Jmp);

	NtQueryInfoFilehk_Entry = AddHookedPage(HvData, QueryInfoFilePa, Jmp, 15);

	Utils::GetJmpCode((ULONG64)QueryInfoFile + 15, (char*)&NtQueryInfoFilehk_Entry->Jmpout.Jmp);



	//DbgPrint("[SETUP] hooks set! \n");
}