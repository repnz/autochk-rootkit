#pragma once
#include <ntifs.h>

typedef struct _FILE_REDIRECTION_ENTRY *PFILE_REDIRECTION_ENTRY;

typedef struct _FILE_REDIRECTION_ENTRY {
	WCHAR SourceFilePath[260];
	WCHAR TargetFilePath[260];
	PFILE_REDIRECTION_ENTRY NextEntry;
} FILE_REDIRECTION_ENTRY, * PFILE_REDIRECTION_ENTRY;

NTSTATUS FsInitializeFileRedirection();

NTSTATUS FsAddFileRedirection(PCWSTR SourceFile, PCWSTR TargetFile);

#define IGNORED_PROCESS_NAME_LENGTH 20

NTSTATUS FsAddIgnoredProcess(PCSTR IgnoredProcessName);

VOID FsFreeFileRedirection();