#pragma once

#include <ntifs.h>
#include <windef.h>
#include <intrin.h>

extern "C" {
    NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
    NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
    NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
    NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
        PEPROCESS SourceProcess,
        PVOID SourceAddress,
        PEPROCESS TargetProcess,
        PVOID TargetAddress,
        SIZE_T BufferSize,
        KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );
    NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(PVOID ImageBase, PCCH RoutineName);
    NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
        PUNICODE_STRING ObjectName,
        ULONG Attributes,
        PACCESS_STATE AccessState,
        ACCESS_MASK DesiredAccess,
        POBJECT_TYPE ObjectType,
        KPROCESSOR_MODE AccessMode,
        PVOID ParseContext,
        PVOID* Object
    );
    NTSYSAPI POBJECT_TYPE* IoDriverObjectType;

    NTSTATUS NTAPI ObCreateObject(
        KPROCESSOR_MODE ProbeMode,
        POBJECT_TYPE ObjectType,
        POBJECT_ATTRIBUTES ObjectAttributes,
        KPROCESSOR_MODE OwnershipMode,
        PVOID ParseContext,
        ULONG ObjectBodySize,
        ULONG PagedPoolCharge,
        ULONG NonPagedPoolCharge,
        PVOID* Object
    );

    VOID NTAPI ObMakeTemporaryObject(PVOID Object);
    UINT64 NTAPI KeQueryUnbiasedInterruptTime();
}

// Prime+Probe cache side channel configuration
#define CACHE_LINE_SIZE 64
#define CACHE_SETS 64              
#define CACHE_WAYS 8               
#define PROBE_ADDRESSES_PER_SET 16 
#define TIMING_THRESHOLD 200       
#define MAX_DATA_BITS 32
#define COMMUNICATION_ROUNDS 4


#define RW_OP_READ 1
#define RW_OP_WRITE 2
#define RW_OP_GET_BASE 3
#define RW_OP_GET_PEB 4

// R/W structures for cache side channel communication
typedef struct _CACHE_RW_REQUEST {
    ULONG operation_type;
    ULONG process_id;
    ULONG64 target_address;
    ULONG size;
    ULONG64 data_value;
    BOOLEAN completed;
    NTSTATUS status;
} CACHE_RW_REQUEST, * PCACHE_RW_REQUEST;

typedef struct _CACHE_RW_RESPONSE {
    ULONG64 data_value;
    ULONG64 base_address;
    NTSTATUS status;
    BOOLEAN valid;
} CACHE_RW_RESPONSE, * PCACHE_RW_RESPONSE;

// Prime+Probe structures
typedef struct _PROBE_SET {
    PVOID addresses[PROBE_ADDRESSES_PER_SET];
    ULONG64 baseline_times[PROBE_ADDRESSES_PER_SET];
    ULONG64 probe_times[PROBE_ADDRESSES_PER_SET];
    BOOLEAN evicted;
    ULONG cache_set_index;
} PROBE_SET, * PPROBE_SET;

typedef struct _PRIME_PROBE_CONTEXT {
    PROBE_SET sets[CACHE_SETS];
    PVOID probe_memory_pool;
    SIZE_T pool_size;
    ULONG current_data;
    ULONG sequence_number;
    BOOLEAN initialized;
    ULONG64 calibration_threshold;

    // R/W communication buffers
    CACHE_RW_REQUEST pending_request;
    CACHE_RW_RESPONSE last_response;
    BOOLEAN request_pending;
    BOOLEAN response_ready;
} PRIME_PROBE_CONTEXT, * PPRIME_PROBE_CONTEXT;

NTSTATUS read_memory(ULONG process_id, ULONG64 address, PVOID buffer, SIZE_T size);
NTSTATUS write_memory(ULONG process_id, ULONG64 address, PVOID buffer, SIZE_T size);
ULONG64 get_process_base(ULONG process_id);
ULONG64 get_process_peb(ULONG process_id);

VOID process_cache_rw_request();
ULONG_PTR get_cache_set_index(PVOID address);
ULONG64 measure_access_time_precise(PVOID address);

NTSTATUS initialize_prime_probe_memory();
VOID calibrate_timing_thresholds();
VOID prime_cache_sets(ULONG data_bits);
ULONG probe_cache_sets();
VOID encode_data_prime_probe(ULONG data);
ULONG decode_data_prime_probe();

VOID cache_communication_dpc(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
VOID cleanup_prime_probe_memory();

NTSTATUS x_cache_io_handler(PDEVICE_OBJECT dev, PIRP irp);
NTSTATUS x_cache_dispatch(PDEVICE_OBJECT dev, PIRP irp);
void x_cache_unload(PDRIVER_OBJECT drv);

NTSTATUS create_driver(NTSTATUS(*entry_point)(DRIVER_OBJECT*, UNICODE_STRING*));
NTSTATUS x_cache_init(PDRIVER_OBJECT drv, PUNICODE_STRING reg);

extern UNICODE_STRING g_cache_dname;
extern UNICODE_STRING g_cache_sname;
extern PRIME_PROBE_CONTEXT g_pp_context;
extern KTIMER g_communication_timer;
extern KDPC g_communication_dpc;
extern BOOLEAN g_timer_initialized;
extern KSPIN_LOCK g_cache_lock;
extern ULONG g_sequence_counter;
