#pragma once
#include "Utils.h"

struct NPTHOOK_ENTRY
{
	PT_ENTRY_64* NptEntry1;
	PT_ENTRY_64* NptEntry2;
	union
	{
		struct Trampoline
		{
			char	OriginalBytes[15];
			char	Jmp[6];
			PVOID	OriginalFunc;
		} Jmpout;
		char	Shellcode[64];
	};

	LIST_ENTRY	HookList;
};

NPTHOOK_ENTRY*	GetHookByPhysicalPage(HYPERVISOR_DATA* HvData, UINT64 PagePhysical);
NPTHOOK_ENTRY*	GetHookByOldFuncAddress(HYPERVISOR_DATA* HvData, PVOID	FuncAddr);
NPTHOOK_ENTRY*	AddHookedPage(HYPERVISOR_DATA* HvData, PVOID PhysicalAddr, ULONG64	NCr3, char* patch, int PatchLen);

void	SetAllPagesExecute(VPROCESSOR_DATA* VpData, bool execute, PDPTE_64* SingledOutPdpte,
	PDE_64* SingledOutPde, PTE_64* SingledOutPte);

void	SetHooks(HYPERVISOR_DATA*	HvData);


extern ULONG64	CopyPage;