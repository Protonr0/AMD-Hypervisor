#include "hook_handler.h"
#include "npt_hook.h"
#include "npt_setup.h"

extern bool
IsProcessorReadyForVmrun(VMCB* GuestVmcb, SEGMENT_ATTRIBUTE CsAttr);

enum VMEXIT_CODES
{
    VMEXIT_CPUID = 0x72,
    VMEXIT_MSR = 0x7C,
    VMEXIT_VMRUN = 0x80,
    VMEXIT_VMMCALL = 0x81,
    VMEXIT_NPF = 0x400,
    VMEXIT_PF = 0x4E,
    VMEXIT_INVALID = -1,
    VMEXIT_GP = 0x4D,
};

void
InjectException(VPROCESSOR_DATA* Vpdata, int vector, int ErrorCode = 0)
{
    EVENTINJ EventInj;

    EventInj.Vector = vector;
    EventInj.Type = 3;
    EventInj.Valid = 1;

    if (ErrorCode != 0) {
        EventInj.PushErrorCode = 1;
        EventInj.ErrorCode = ErrorCode;
    }

    Vpdata->GuestVmcb.ControlArea.EventInj = EventInj.Flags;
}


void
HandleNestedPageFault(VPROCESSOR_DATA* VpData, GUEST_REGISTERS* GuestContext)
{
    NPF_EXITINFO1 ExitInfo1;

    ExitInfo1.AsUInt64 = VpData->GuestVmcb.ControlArea.ExitInfo1;

    ULONG64 FailAddress = VpData->GuestVmcb.ControlArea.ExitInfo2;

    PHYSICAL_ADDRESS NCr3;

    NCr3.QuadPart = VpData->GuestVmcb.ControlArea.NCr3;

    if (ExitInfo1.Fields.Valid == 0) {
        int NumberOfBytes = VpData->GuestVmcb.ControlArea.NumOfBytesFetched;

        UINT8* InstructionBytes =
            VpData->GuestVmcb.ControlArea.GuestInstructionBytes;

        // DbgPrint("[VMEXIT] Nested Page Fault occured!! ExitInfo1: %p \n",
        // ExitInfo1.AsUInt64); DbgPrint("[VMEXIT] faulting guest physical
        // address: %p \n", FailAddress); 
        // DbgPrint("[VMEXIT] building new NPT entry for guest... fail address %p \n", FailAddress);

        PML4E_64* Pml4Base = (PML4E_64*)MmGetVirtualForPhysical(NCr3);

        PTE_64* Pte64 = AssignNPTEntry((PML4E_64*)Pml4Base, FailAddress, true);

        // DbgPrint("[VMEXIT] faulting PTE: %p \n", Pte64);

        return;
    }

    if (ExitInfo1.Fields.Execute == 1) {
        /*	swap NCR3 to achieve lightning speeds	*/

        NPTHOOK_ENTRY* nptHook = 0;

        PHYSICAL_ADDRESS FailAddresss;
        FailAddresss.QuadPart = FailAddress;

        if (PAGE_ALIGN(NtQueryInformationFile) == (PVOID)MmGetVirtualForPhysical(FailAddresss))
        {
            nptHook = NtQueryInfoFilehk_Entry;
        }

        //DbgPrint("===================================================\n failaddress %p \n", MmGetVirtualForPhysical(FailAddresss));
        //DbgPrint("exit info: %p \n", ExitInfo1);
        //DbgPrint("Fail Physical address %p, guest RIP %p \n", FailAddress, VpData->GuestVmcb.SaveStateArea.Rip);
        //DbgPrint("current NCr3: %p \n", VpData->GuestVmcb.ControlArea.NCr3);
        //DbgPrint("original page bytes: ");
        //for (int i = 0; i < 15; ++i)
        //{
        //    DbgPrint(" %02x ", (UCHAR)((UCHAR*)VpData->GuestVmcb.SaveStateArea.Rip)[i]);
        //}
        //DbgPrint("\n");

        if (nptHook) {
            //  DbgPrint("switching to hook address \n");
            VpData->GuestVmcb.ControlArea.NCr3 = g_HvData->SecondaryNCr3;
        }
        else {
            VpData->GuestVmcb.ControlArea.NCr3 = g_HvData->PrimaryNCr3;
        }

        VpData->GuestVmcb.ControlArea.VmcbClean &= 0xFFFFFFEF;
        VpData->GuestVmcb.ControlArea.TlbControl = 3;
    }
}

void
HandleCpuidExit(VPROCESSOR_DATA* VpData, GUEST_REGISTERS* GuestRegisters)
{
    VpData->GuestVmcb.SaveStateArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

void
HandleMsrExit(VPROCESSOR_DATA* VpData, GUEST_REGISTERS* GuestRegisters)
{
    VpData->GuestVmcb.SaveStateArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

void
HandleVmmcall(VPROCESSOR_DATA* VpData,
    GUEST_REGISTERS* GuestRegisters,
    bool* EndVM)
{
    int Registers[4];

    UINT64 Leaf = GuestRegisters->Rcx;

    switch (Leaf) {
    case VMMCALL_HYPERVISOR_SIG: {
        Registers[0] = 'epyH'; /*	"HyperCheatzz"	*/
        Registers[1] = 'ehCr';
        Registers[2] = 'zzta';

        break;
    }
    case VMMCALL_ENABLE_HOOKS: {
        InitializeHookList(g_HvData);

        SetHooks(g_HvData);
        __debugbreak();
        KeInvalidateAllCaches();

        break;
    }
    case VMMCALL_END_HV: {
        *EndVM = true;
        break;
    }
    default:
        break;
    }

    VpData->GuestVmcb.SaveStateArea.Rax = Registers[0];
    GuestRegisters->Rbx = Registers[1];
    GuestRegisters->Rcx = Registers[2];
    GuestRegisters->Rdx = Registers[3];

    VpData->GuestVmcb.SaveStateArea.Rip = VpData->GuestVmcb.ControlArea.NRip;
}

/*
        Vpdata = rcx
        Guest registers = rdx
*/
PDE_2MB_64* GuestQueryInfoFilePte = 0;
extern "C" bool
HandleVmexit(VPROCESSOR_DATA * VpData, GUEST_REGISTERS * GuestRegisters)
{
    /*	load host extra state	*/
    __svm_vmload(VpData->HostVmcbPa);

    bool EndVm = false;

    switch ((int)VpData->GuestVmcb.ControlArea.ExitCode) {
    case VMEXIT_CPUID: {
        HandleCpuidExit(VpData, GuestRegisters);
        break;
    }
    case VMEXIT_MSR: {
        HandleMsrExit(VpData, GuestRegisters);
        break;
    }
    case VMEXIT_VMRUN: {
        InjectException(VpData, 13);
        break;
    }
    case VMEXIT_VMMCALL: {
        HandleVmmcall(VpData, GuestRegisters, &EndVm);
        break;
    }
    case VMEXIT_PF: {
        DbgPrint("[VMEXIT] page fault occured at address %p \n",
            VpData->GuestVmcb.ControlArea.ExitInfo2);
        DbgPrint("[VMEXIT] guest RIP %p \n", VpData->GuestVmcb.SaveStateArea.Rip);
        break;
    }
    case VMEXIT_NPF: {
        HandleNestedPageFault(VpData, GuestRegisters);
        break;
    }
    case VMEXIT_GP: {
        char InstructionBytes[16] = { 0 };
        memcpy(InstructionBytes, (PVOID)VpData->GuestVmcb.SaveStateArea.Rip, 16);

        CR3 cr3;
        cr3.Flags = __readcr3();

        GuestQueryInfoFilePte = (PDE_2MB_64*)Utils::GetPte(
            NtQueryInformationFile, cr3.AddressOfPageDirectory << PAGE_SHIFT);

        KeBugCheckEx(MANUALLY_INITIATED_CRASH,
            (ULONG64)InstructionBytes,
            (ULONG64)GuestRegisters,
            VpData->GuestVmcb.SaveStateArea.Rip,
            (ULONG64)GuestQueryInfoFilePte);

        InjectException(VpData, 13, 0xC0000005);
        break;
    }
    case VMEXIT_INVALID: {
        __debugbreak();
        SEGMENT_ATTRIBUTE CsAttrib;
        CsAttrib.AsUInt16 = VpData->GuestVmcb.SaveStateArea.CsAttrib;

        IsProcessorReadyForVmrun(&VpData->GuestVmcb, CsAttrib);

        break;
    }
    default:
        DbgPrint("[VMEXIT] huh?? wtf why did I exit ?? exit code %p \n",
            VpData->GuestVmcb.ControlArea.ExitCode);
        break;
    }

    if (EndVm) {
        /*
                When we end the VM operation, we transform host state into guest
           context, and continue from there as host

                1. load guest state
                2. disable IF
                3. enable GIF
                4. disable SVME
                5. restore EFLAGS and re enable IF
                6. set RBX to RIP
                7. set RCX to RSP
                8. return and jump back
        */

        __svm_vmload(VpData->GuestVmcbPa);

        __svm_stgi();
        _disable();

        EFER_MSR Msr;

        Msr.Flags = __readmsr(AMD_EFER);
        Msr.SVME = 0;

        __writemsr(AMD_EFER, Msr.Flags);
        __writeeflags(VpData->GuestVmcb.SaveStateArea.Rflags);
    }

    return EndVm;
}