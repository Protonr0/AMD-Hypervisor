#include "npt_setup.h"
#include "npt_hook.h"
#include "hook_handler.h"

int	CoreCount = 0;
VPROCESSOR_DATA* g_VpData[32] = { 0 };

EXTERN_C VOID _sgdt(_Out_ PVOID Descriptor);

EXTERN_C VOID NTAPI LaunchVm(PVOID VmLaunchParams);

EXTERN_C int NTAPI svm_vmmcall(UINT64	Rcx, UINT64	Rdx, UINT64	R8, UINT64	 R9);




/*	Copy bits bits 55:52 and 47:40	*/
SEGMENT_ATTRIBUTE	GetSegmentAttributes(UINT16 SegmentSelector, ULONG64 GdtBase)
{	
	SEGMENT_SELECTOR	SegSelector;

	SegSelector.Flags = SegmentSelector;

	SEGMENT_DESCRIPTOR	SegDescriptor = ((SEGMENT_DESCRIPTOR*)GdtBase)[SegSelector.Index];

	SEGMENT_ATTRIBUTE	attribute;

	attribute.Fields.Type = SegDescriptor.Fields.Type;
	attribute.Fields.System = SegDescriptor.Fields.System;
	attribute.Fields.Dpl = SegDescriptor.Fields.Dpl;
	attribute.Fields.Present = SegDescriptor.Fields.Present;
	attribute.Fields.Avl = SegDescriptor.Fields.Avl;
	attribute.Fields.LongMode = SegDescriptor.Fields.LongMode;
	attribute.Fields.DefaultBit = SegDescriptor.Fields.DefaultBit;
	attribute.Fields.Granularity = SegDescriptor.Fields.Granularity;
	attribute.Fields.Reserved1 = 0;

	return attribute;
}


void	ConfigureProcessor(VPROCESSOR_DATA* VpData, PCONTEXT ContextRecord, HYPERVISOR_DATA* Hvdata)
{
	VpData->GuestVmcbPa = MmGetPhysicalAddress(&VpData->GuestVmcb).QuadPart;	
	VpData->HostVmcbPa = MmGetPhysicalAddress(&VpData->HostVmcb).QuadPart;
	VpData->Self = VpData;


	VpData->GuestVmcb.ControlArea.NCr3 = g_HvData->PrimaryNCr3;
	VpData->GuestVmcb.ControlArea.NpEnable = (1UL << 0);

	DESCRIPTOR_TABLE_REGISTER	Gdtr, idtr;

	_sgdt(&Gdtr);
	__sidt(&idtr);

	VpData->GuestVmcb.ControlArea.InterceptVec4 |= INTERCEPT_VMMCALL;
	VpData->GuestVmcb.ControlArea.InterceptVec4 |= INTERCEPT_VMRUN;
	//VpData->GuestVmcb.ControlArea.InterceptException |= (1UL << 14);	page fault
	//VpData->GuestVmcb.ControlArea.InterceptException |= (1UL << 13);	//GP fault

	VpData->GuestVmcb.ControlArea.GuestAsid = 1;
	VpData->GuestVmcb.SaveStateArea.Cr0 = __readcr0();	
	VpData->GuestVmcb.SaveStateArea.Cr2 = __readcr2();
	VpData->GuestVmcb.SaveStateArea.Cr3 = __readcr3();
	VpData->GuestVmcb.SaveStateArea.Cr4 = __readcr4();
	

	VpData->GuestVmcb.SaveStateArea.Rip = ContextRecord->Rip;
	VpData->GuestVmcb.SaveStateArea.Rax = ContextRecord->Rax;
	VpData->GuestVmcb.SaveStateArea.Rsp = ContextRecord->Rsp;
	VpData->GuestVmcb.SaveStateArea.Rflags = __readeflags();
	VpData->GuestVmcb.SaveStateArea.Efer = __readmsr(AMD_EFER);
	VpData->GuestVmcb.SaveStateArea.GPat = __readmsr(AMD_MSR_PAT);

	VpData->GuestVmcb.SaveStateArea.GdtrLimit = Gdtr.Limit;
	VpData->GuestVmcb.SaveStateArea.GdtrBase = Gdtr.Base;
	VpData->GuestVmcb.SaveStateArea.IdtrLimit = idtr.Limit;
	VpData->GuestVmcb.SaveStateArea.IdtrBase = idtr.Base;
	
	VpData->GuestVmcb.SaveStateArea.CsLimit = GetSegmentLimit(ContextRecord->SegCs);
	VpData->GuestVmcb.SaveStateArea.DsLimit = GetSegmentLimit(ContextRecord->SegDs);
	VpData->GuestVmcb.SaveStateArea.EsLimit = GetSegmentLimit(ContextRecord->SegEs);
	VpData->GuestVmcb.SaveStateArea.SsLimit = GetSegmentLimit(ContextRecord->SegSs);

	VpData->GuestVmcb.SaveStateArea.CsSelector = ContextRecord->SegCs;
	VpData->GuestVmcb.SaveStateArea.DsSelector = ContextRecord->SegDs;
	VpData->GuestVmcb.SaveStateArea.EsSelector = ContextRecord->SegEs;
	VpData->GuestVmcb.SaveStateArea.SsSelector = ContextRecord->SegSs;


	VpData->GuestVmcb.SaveStateArea.CsAttrib = GetSegmentAttributes(ContextRecord->SegCs, Gdtr.Base).AsUInt16;
	VpData->GuestVmcb.SaveStateArea.DsAttrib = GetSegmentAttributes(ContextRecord->SegDs, Gdtr.Base).AsUInt16;
	VpData->GuestVmcb.SaveStateArea.EsAttrib = GetSegmentAttributes(ContextRecord->SegEs, Gdtr.Base).AsUInt16;
	VpData->GuestVmcb.SaveStateArea.SsAttrib = GetSegmentAttributes(ContextRecord->SegSs, Gdtr.Base).AsUInt16;


	DbgPrint("VpData->GuestVmcb: %p\n", VpData->GuestVmcb);
	DbgPrint("VpData->GuestVmcbPa: %p\n", VpData->GuestVmcbPa);

	__svm_vmsave(VpData->GuestVmcbPa);

	__writemsr(VM_HSAVE_PA, MmGetPhysicalAddress(&VpData->HostSaveArea).QuadPart);

	__svm_vmsave(VpData->HostVmcbPa);
}

bool	IsSvmSupported()
{
	int	cpuInfo[4] = { 0 };

	/*	  CPUID_Fn80000001_ECX.bit_2	*/
	__cpuid(cpuInfo, CPUID_PROCESSOR_AND_PROCESSOR_FEATURE_IDENTIFIERS);

	if ((cpuInfo[2] & (1 << 1)) == 0)
	{
		return false;
	}


	int		VendorNameResult[4];
	char	VendorName[13];

	__cpuid(VendorNameResult, CPUID_MAX_STANDARD_FN_NUMBER_AND_VENDOR_STRING);
	memcpy(VendorName, &VendorNameResult[1], sizeof(int));
	memcpy(VendorName + 4, &VendorNameResult[3], sizeof(int));
	memcpy(VendorName + 8, &VendorNameResult[2], sizeof(int));

	VendorName[12] = '\0';

	DbgPrint("[SETUP] Vendor Name %s \n", VendorName);

	if (strcmp(VendorName, "AuthenticAMD") && strcmp(VendorName, "VmwareVmware"))
	{
		return false;
	}

	return true;
}

bool	IsSvmUnlocked()
{
	VM_CR_MSR	msr;
	msr.Flags = __readmsr(AMD_VM_CR);


	if (msr.SVMLock == 0)
	{
		msr.SVMEDisable = 0;
		msr.SVMLock = 1;
		__writemsr(AMD_VM_CR, msr.Flags);
	}
	else if (msr.SVMEDisable == 1)
	{
		return false;
	}

	return true;
}

void	Enable_Svme()
{
	EFER_MSR	msr;
	msr.Flags = __readmsr(AMD_EFER);
	msr.SVME = 1;
	__writemsr(AMD_EFER, msr.Flags);
}


bool	IsHypervisorPresent(int CoreNumber)
{
	/*	shitty check, switched from vmmcall to pointer check to avoid #UD	*/

	if (g_VpData[CoreNumber] != NULL)
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool	IsProcessorReadyForVmrun(VMCB* GuestVmcb, SEGMENT_ATTRIBUTE CsAttr)
{
	EFER_MSR	efer_msr = { 0 };
	efer_msr.Flags = __readmsr(AMD_EFER);

	if (efer_msr.SVME == 1)
	{
		DbgPrint("SVME is off, invalid state! \n");
		return false;
	}

	if ((efer_msr.reserved2 != 0) || (efer_msr.reserved3 != 0) || (efer_msr.reserved4 != 0))
	{
		DbgPrint("MBZ bit of EFER is set, Invalid state! \n");
		return false;
	}

	CR0	cr0;
	cr0.Flags = __readcr0();

	if ((cr0.CacheDisable == 0) && (cr0.NotWriteThrough == 1))
	{
		DbgPrint("CR0.CD is zero and CR0.NW is set. \n");
		return false;
	}

	if (cr0.Reserved4 != 0)
	{
		DbgPrint("CR0[63:32] are not zero. \n");
		return false;
	}

	RFLAGS	rflags;
	rflags.Flags = __readeflags();

	CR3	cr3;
	CR4	cr4;

	cr3.Flags = __readcr3();
	cr4.Flags = __readcr4();

	if (rflags.Virtual8086ModeFlag == 1 && (cr4.Flags << 23 & 1))
	{
		DbgPrint("CR4.CET=1 and U_CET.SS=1 when EFLAGS.VM=1 \n");
	}

	if ((cr3.Reserved1 != 0) || (cr3.Reserved2 != 0) || (cr4.Reserved1 != 0)
		|| (cr4.Reserved2 != 0) || (cr4.Reserved3 != 0) || (cr4.Reserved4 != 0))
	{
		DbgPrint("cr3 or cr4 MBZ bits are zero. Invalid state rn \n");
		return false;
	}

	DR6	dr6;
	DR7 dr7;

	dr6.Flags = __readdr(6);
	dr7.Flags = __readdr(7);

	if ((dr6.Flags & (0xFFFFFFFF00000000)) || (dr7.Reserved4 != 0))
	{
		DbgPrint("DR6[63:32] are not zero, or DR7[63:32] are not zero. Invalid State! \n");
		return false;
	}

	if (cr0.PagingEnable == 0)
	{
		DbgPrint("Paging disabled, Invalid state! \n");
		return false;
	}

	if (efer_msr.LongModeEnable == 1 && cr0.PagingEnable == 1)
	{
		if (cr4.PhysicalAddressExtension == 0)
		{
			DbgPrint("EFER.LME and CR0.PG are both set and CR4.PAE is zero, Invalid state! \n");
			return false;
		}

		if (cr0.ProtectionEnable == 0)
		{
			DbgPrint("EFER.LME and CR0.PG are both non-zero and CR0.PE is zero, Invalid state! \n");
			return false;
		}

		if (CsAttr.Fields.LongMode != 0 && CsAttr.Fields.LongMode != 0)
		{
			DbgPrint("EFER.LME, CR0.PG, CR4.PAE, CS.L, and CS.D are all non-zero. \n");
			return false;
		}
	}

	if (GuestVmcb->ControlArea.GuestAsid == 0)
	{
		DbgPrint("ASID is equal to zero. Invalid guest state \n");
		return false;
	}

	if (!(GuestVmcb->ControlArea.InterceptVec4 & 1))
	{
		DbgPrint("The VMRUN intercept bit is clear. Invalid state! \n");
		return false;
	}

	DbgPrint("consistency checks passed \n");
	return true;

	/*	to be done: msr and ioio map address checks, and some more. */
}

int ipow(int base, int power)
{
	int start = 1;
	for (int i = 0; i < power; ++i)
	{
		start *= base;
	}

	return start;
}

HYPERVISOR_DATA* g_HvData = 0;
void	VirtualizeAllProcessors()
{
	if (!IsSvmSupported())
	{
		DbgPrint("[SETUP] SVM isn't supported on this processor! \n");
		return;
	}

	if (!IsSvmUnlocked())
	{
		DbgPrint("[SETUP] SVM operation is locked off in BIOS! \n");
		return;
	}

	g_HvData = (HYPERVISOR_DATA*)ExAllocatePool(NonPagedPool, sizeof(HYPERVISOR_DATA));

	BuildNestedPagingTables(&g_HvData->PrimaryNCr3, true);
	BuildNestedPagingTables(&g_HvData->SecondaryNCr3, false);
	BuildNestedPagingTables(&g_HvData->TertiaryNCr3, true);

	DbgPrint("g_HvData->SecondaryNCr3: %p \n", g_HvData->SecondaryNCr3);
	DbgPrint("g_HvData->PrimaryNCr3: %p \n", g_HvData->PrimaryNCr3);

	CoreCount = KeQueryActiveProcessorCount(0);

	for (int i = 0; i < CoreCount; ++i)
	{
		KAFFINITY	Affinity = ipow(2, i);

		KeSetSystemAffinityThread(Affinity);


		DbgPrint("============================================================================= \n");
		DbgPrint("[SETUP] amount of active processors %i \n", CoreCount);
		DbgPrint("[SETUP] Currently running on core %i \n", i);


		CONTEXT* pContext = (CONTEXT*)ExAllocatePoolZero(NonPagedPool, sizeof(CONTEXT), 'Cotx');

		RtlCaptureContext(pContext);

		if (IsHypervisorPresent(i) == false)
		{
			Enable_Svme();

			g_VpData[i] = (VPROCESSOR_DATA*)ExAllocatePoolZero(NonPagedPool, sizeof(VPROCESSOR_DATA), 'Vmcb');

			ConfigureProcessor(g_VpData[i], pContext, g_HvData);


			SEGMENT_ATTRIBUTE	CsAttrib;

			CsAttrib.AsUInt16 = g_VpData[i]->GuestVmcb.SaveStateArea.CsAttrib;

			if (IsProcessorReadyForVmrun(&g_VpData[i]->GuestVmcb, CsAttrib))
			{
				LaunchVm(&g_VpData[i]->GuestVmcbPa);
			}
			else
			{
				DbgPrint("[SETUP] A problem occured!! invalid guest state \n");
				__debugbreak();
			}
		}
		else
		{
			DbgPrint("===================== Hypervisor Successfully Launched rn !! =============================\n \n");
		}
	}
}


void	HypervisorEntry()
{
	PMDL mdl = IoAllocateMdl(NtQueryInformationFile, PAGE_SIZE, FALSE, FALSE, nullptr);

	//DbgPrint("MDL: %p \n", mdl);
	//DbgPrint("Ntqueryinfofile_handler: %p \n", NtQueryInfoFile_handler);

	MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

	NtQueryInformationFile(0, 0, 0, 0, FileBasicInformation);
	CR3	cr3;
	cr3.Flags = __readcr3();
	PT_ENTRY_64* sjidod = Utils::GetPte(NtQueryInformationFile, cr3.AddressOfPageDirectory << PAGE_SHIFT);
	DbgPrint("ntqueryinfofile page table: %p\n", *sjidod);
	DbgPrint("ntqueryinfofile page: %p \n", PAGE_ALIGN(NtQueryInformationFile));
	DbgPrint("current  cr3 %p \n", cr3.AddressOfPageDirectory << PAGE_SHIFT);


	VirtualizeAllProcessors();

	NtQueryInformationFile(0, 0, 0, 0, FileBasicInformation);

	LARGE_INTEGER	time;
	time.QuadPart = -600ll * 10 * 1000;
	KeDelayExecutionThread(KernelMode, TRUE, &time);

	svm_vmmcall(VMMCALL_ENABLE_HOOKS, 0, 0, 0);

	DbgPrint("hello!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
	__debugbreak();

	for (int i = 0; i < 4; ++i)
	{
		NtQueryInformationFile(0, 0, 0, 0, FileBasicInformation);
	}
	DbgPrint("ntqueryinformationfile test called. \n");

	PsTerminateSystemThread(STATUS_SUCCESS);
}


ULONG64	CopyPage;
NTSTATUS	MapperEntry(DRIVER_OBJECT* DriverObject, PUNICODE_STRING	RegistryPath)
{
	CopyPage = (ULONG64)ExAllocatePool(NonPagedPool, PAGE_SIZE);

	DbgPrint("CopyPage %p \n", CopyPage);


	HANDLE	hThread;

	PsCreateSystemThread(&hThread, GENERIC_ALL, NULL, NULL, NULL, (PKSTART_ROUTINE)HypervisorEntry, NULL);


	LARGE_INTEGER	time;
	time.QuadPart = -600ll * 10 * 1000;
	KeDelayExecutionThread(KernelMode, TRUE, &time);


	/*HANDLE	LogThread;

	PsCreateSystemThread(&LogThread, GENERIC_ALL, NULL, NULL, NULL, (PKSTART_ROUTINE)LogInfo, NULL);*/

	return	STATUS_SUCCESS;
}