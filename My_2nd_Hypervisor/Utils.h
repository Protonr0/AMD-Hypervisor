#pragma once
#include "Global.h"

typedef int (*PageTableOperation)(PT_ENTRY_64*);

namespace Utils
{
    PVOID		GetVaFromPfn(ULONG64	pfn);
	PFN_NUMBER	GetPfnFromVa(ULONG64	Va);

	PT_ENTRY_64* GetPte(PVOID VirtualAddress, ULONG64 Pml4BasePa, PageTableOperation Operation = NULL);
	PT_ENTRY_64* GetPte(PVOID VirtualAddress, ULONG64 Pml4BasePa, PDPTE_64** PdpteResult, PDE_64** PdeResult);

	KIRQL	disableWP();
	void	enableWP(KIRQL tempirql);

	void	PlaceJmp(ULONG64  addr, ULONG64	jmpAddr, BYTE* oldBytes);
	void    GetJmpCode(ULONG64 jmpAddr, char* output);

	PVOID	GetSystemRoutineAddress(wchar_t* RoutineName, PVOID* RoutinePhysical = NULL);
}