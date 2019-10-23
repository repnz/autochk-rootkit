#pragma once
#include <ntifs.h>	

// Debugging Macros
//
// Common Format Specifiers:
//
// %d - ULONG
// %p - Pointer. (Typically used with 0x%p)
// %s - STR
// %ws - WSTR
// %Z - STRING object pointer
// %wZ - UNICODE_STRING object pointer
//

#define ALLOC_TAG 'rexE'

#define DRIVER_PREFIX "AutochkRootkit: (%s:%d):   "

#define _D(Level, Fmt) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, Level, DRIVER_PREFIX Fmt "\n", __FUNCTION__, __LINE__))

#define _D_ARGS(Level, Fmt, ...) \
    KdPrintEx((DPFLTR_IHVDRIVER_ID, Level, DRIVER_PREFIX Fmt "\n", __FUNCTION__, __LINE__, __VA_ARGS__))

#define D_INFO(Fmt) \
    _D(DPFLTR_INFO_LEVEL, Fmt)

#define D_INFO_ARGS(Fmt, ...) \
    _D_ARGS(DPFLTR_INFO_LEVEL, Fmt, __VA_ARGS__)

#define D_ERROR(Fmt) \
     _D(DPFLTR_ERROR_LEVEL, Fmt)

#define D_ERROR_ARGS(Fmt, ...) \
    _D_ARGS(DPFLTR_ERROR_LEVEL, Fmt,__VA_ARGS__)

#define D_ERROR_STATUS(Fmt, Status) \
    _D_ARGS(DPFLTR_ERROR_LEVEL, Fmt " (NTSTATUS: 0x%08X)\n", Status)

#define D_ERROR_STATUS_ARGS(Fmt, Status, ...) \
    _D_ARGS(DPFLTR_ERROR_LEVEL, Fmt " (NTSTATUS: 0x%08X)\n", __VA_ARGS__, Status)

#define D_TRACE(Fmt) \
    _D(DPFLTR_TRACE_LEVEL, Fmt)

#define D_TRACE_ARGS(Fmt, ...) \
    _D_ARGS(DPFLTR_TRACE_LEVEL, Fmt, __VA_ARGS__)