#include "Utils.h"

namespace Utils
{
    KIRQL disableWP()
    {
        KIRQL	tempirql = KeRaiseIrqlToDpcLevel();

        ULONG64  cr0 = __readcr0();

        cr0 &= 0xfffffffffffeffff;

        __writecr0(cr0);

        _disable();

        return tempirql;

    }


    void enableWP(KIRQL		tempirql)
    {
        ULONG64	cr0 = __readcr0();

        cr0 |= 0x10000;

        _enable();

        __writecr0(cr0);

        KeLowerIrql(tempirql);
    }


    PVOID	GetVaFromPfn(ULONG64 pfn)
    {
        PHYSICAL_ADDRESS pa;
        pa.QuadPart = pfn << PAGE_SHIFT;

        return MmGetVirtualForPhysical(pa);
    }

    PFN_NUMBER	GetPfnFromVa(ULONG64 Va)
    {
        return MmGetPhysicalAddress((PVOID)Va).QuadPart >> PAGE_SHIFT;
    }

    PT_ENTRY_64* GetPte(PVOID VirtualAddress, ULONG64 Pml4BasePa, PageTableOperation Operation)
    {
        ADDRESS_TRANSLATION_HELPER helper;
        PT_ENTRY_64* finalEntry;


        helper.AsUInt64 = (UINT64)VirtualAddress;

        PHYSICAL_ADDRESS    addr;

        addr.QuadPart = Pml4BasePa;

        PML4E_64* pml4;
        PML4E_64* pml4e;

        pml4 = (PML4E_64*)MmGetVirtualForPhysical(addr);

        pml4e = &pml4[helper.AsIndex.Pml4];

        if (Operation)
        {
            Operation((PT_ENTRY_64*)pml4e);
        }

        if (pml4e->Present == FALSE)
        {
            return (PT_ENTRY_64*)pml4e;
        }

        PDPTE_64* pdpt;
        PDPTE_64* pdpte;

        pdpt = (PDPTE_64*)GetVaFromPfn(pml4e->PageFrameNumber);

        pdpte = &pdpt[helper.AsIndex.Pdpt];

        if (Operation)
        {
            Operation((PT_ENTRY_64*)pdpte);
        }

        if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE))
        {
            return (PT_ENTRY_64*)pdpte;
        }

        PDE_64* pd;
        PDE_64* pde;

        pd = (PDE_64*)GetVaFromPfn(pdpte->PageFrameNumber);

        pde = &pd[helper.AsIndex.Pd];

        if (Operation)
        {
            Operation((PT_ENTRY_64*)pde);
        }

        if ((pde->Present == FALSE) || (pde->LargePage != FALSE))
        {
            return (PT_ENTRY_64*)pde;
        }


        PTE_64* pt;
        PTE_64* pte;

        
        pt = (PTE_64*)GetVaFromPfn(pde->PageFrameNumber);

        pte = &pt[helper.AsIndex.Pt];

        if (Operation)
        {
            Operation((PT_ENTRY_64*)pte);
        }

        return  (PT_ENTRY_64*)pte;
    }
    PT_ENTRY_64* GetPte(PVOID VirtualAddress, ULONG64 Pml4BasePa, PDPTE_64** PdpteResult, PDE_64** PdeResult)
    {
        ADDRESS_TRANSLATION_HELPER helper;
        PT_ENTRY_64* finalEntry;


        helper.AsUInt64 = (UINT64)VirtualAddress;

        PHYSICAL_ADDRESS    addr;

        addr.QuadPart = Pml4BasePa;


        PML4E_64* pml4;
        PML4E_64* pml4e;

        pml4 = (PML4E_64*)MmGetVirtualForPhysical(addr);

        pml4e = &pml4[helper.AsIndex.Pml4];

        if (pml4e->Present == FALSE)
        {
            return (PT_ENTRY_64*)pml4e;
        }


        PDPTE_64* pdpt;
        PDPTE_64* pdpte;

        pdpt = (PDPTE_64*)GetVaFromPfn(pml4e->PageFrameNumber);

        *PdpteResult = pdpte = &pdpt[helper.AsIndex.Pdpt];

        if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE))
        {
            return (PT_ENTRY_64*)pdpte;
        }


        PDE_64* pd;
        PDE_64* pde;

        pd = (PDE_64*)GetVaFromPfn(pdpte->PageFrameNumber);

        *PdeResult = pde = &pd[helper.AsIndex.Pd];

        if ((pde->Present == FALSE) || (pde->LargePage != FALSE))
        {
            return (PT_ENTRY_64*)pde;
        }


        PTE_64* pt;
        PTE_64* pte;


        pt = (PTE_64*)GetVaFromPfn(pde->PageFrameNumber);

        pte = &pt[helper.AsIndex.Pt];

        return  (PT_ENTRY_64*)pte;
    }

    void	PlaceJmp(ULONG64	addr, ULONG64	jmpAddr, BYTE* oldBytes)
    {
        KIRQL	tempIRQL = Utils::disableWP();

        if (oldBytes != NULL)
        {
            memcpy(oldBytes, (PVOID64)addr, 12);
        }

        char*   JmpRax = "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xE0";

        memcpy(JmpRax + 2, &jmpAddr, 8);
        memcpy((PVOID64)addr, JmpRax, 12);

        Utils::enableWP(tempIRQL);

        return;
    }

    void    GetJmpCode(ULONG64 jmpAddr, char* output)
    {
        char JmpIndirect[15] = "\xFF\x25\x00\x00\x00\x00\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC";

        memcpy(JmpIndirect + 6, &jmpAddr, sizeof(PVOID));
        memcpy((PVOID)output, JmpIndirect, 14);
    }

    PVOID	GetSystemRoutineAddress(wchar_t* RoutineName, PVOID* RoutinePhysical)
    {
        UNICODE_STRING	Routine_Name = RTL_CONSTANT_STRING(RoutineName);

        PVOID	Routine = MmGetSystemRoutineAddress(&Routine_Name);

        PVOID	RoutinePa = (PVOID)MmGetPhysicalAddress(Routine).QuadPart;

        if (RoutinePhysical)
        {
            *RoutinePhysical = RoutinePa;
        }

        return Routine;
    }
}