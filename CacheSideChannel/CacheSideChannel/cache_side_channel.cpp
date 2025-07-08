#include "cache_driver.h"

// Global variables
UNICODE_STRING g_cache_dname;
UNICODE_STRING g_cache_sname;
PRIME_PROBE_CONTEXT g_pp_context = { 0 };
KTIMER g_communication_timer;
KDPC g_communication_dpc;
BOOLEAN g_timer_initialized = FALSE;
KSPIN_LOCK g_cache_lock;
ULONG g_sequence_counter = 0;


NTSTATUS read_memory(ULONG process_id, ULONG64 address, PVOID buffer, SIZE_T size) {
    PEPROCESS target_process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T bytes_copied = 0;

    __try {
        status = PsLookupProcessByProcessId((HANDLE)process_id, &target_process);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = MmCopyVirtualMemory(
            target_process,
            (PVOID)address,
            PsGetCurrentProcess(),
            buffer,
            size,
            KernelMode,
            &bytes_copied
        );
        ObDereferenceObject(target_process);
        return status;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (target_process) {
            ObDereferenceObject(target_process);
        }
        return STATUS_ACCESS_VIOLATION;
    }
}
NTSTATUS write_memory(ULONG process_id, ULONG64 address, PVOID buffer, SIZE_T size) {
    PEPROCESS target_process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T bytes_copied = 0;

    __try {
        status = PsLookupProcessByProcessId((HANDLE)process_id, &target_process);
        if (!NT_SUCCESS(status)) {
            return status;
        }
        status = MmCopyVirtualMemory(
            PsGetCurrentProcess(),
            buffer,
            target_process,
            (PVOID)address,
            size,
            KernelMode,
            &bytes_copied
        );

        ObDereferenceObject(target_process);
        return status;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (target_process) {
            ObDereferenceObject(target_process);
        }
        return STATUS_ACCESS_VIOLATION;
    }
}

ULONG64 get_process_base(ULONG process_id) {
    PEPROCESS target_process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG64 base_address = 0;
    __try {
        status = PsLookupProcessByProcessId((HANDLE)process_id, &target_process);
        if (NT_SUCCESS(status)) {
            base_address = (ULONG64)PsGetProcessSectionBaseAddress(target_process);
            ObDereferenceObject(target_process);
        }
        return base_address;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (target_process) {
            ObDereferenceObject(target_process);
        }
        return 0;
    }
}
ULONG64 get_process_peb(ULONG process_id) {
    PEPROCESS target_process = NULL;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG64 peb_address = 0;

    __try {
        status = PsLookupProcessByProcessId((HANDLE)process_id, &target_process);
        if (NT_SUCCESS(status)) {
            peb_address = (ULONG64)PsGetProcessPeb(target_process);
            ObDereferenceObject(target_process);
        }
        return peb_address;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (target_process) {
            ObDereferenceObject(target_process);
        }
        return 0;
    }
}
VOID process_cache_rw_request() {
    if (!g_pp_context.request_pending) return;

    PCACHE_RW_REQUEST req = &g_pp_context.pending_request;
    PCACHE_RW_RESPONSE resp = &g_pp_context.last_response;

    RtlZeroMemory(resp, sizeof(CACHE_RW_RESPONSE));

    switch (req->operation_type) {
    case RW_OP_READ: {
        ULONG64 read_value = 0;
        NTSTATUS status = read_memory(req->process_id, req->target_address, &read_value, min(req->size, sizeof(ULONG64)));

        resp->data_value = read_value;
        resp->status = status;
        resp->valid = TRUE;
        break;
    }

    case RW_OP_WRITE: {
        NTSTATUS status = write_memory(req->process_id, req->target_address, &req->data_value, min(req->size, sizeof(ULONG64)));

        resp->data_value = req->data_value;
        resp->status = status;
        resp->valid = TRUE;
        break;
    }

    case RW_OP_GET_BASE: {
        ULONG64 base_addr = get_process_base(req->process_id);

        resp->base_address = base_addr;
        resp->data_value = base_addr;
        resp->status = base_addr ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        resp->valid = TRUE;
        break;
    }

    case RW_OP_GET_PEB: {
        ULONG64 peb_addr = get_process_peb(req->process_id);

        resp->base_address = peb_addr;
        resp->data_value = peb_addr;
        resp->status = peb_addr ? STATUS_SUCCESS : STATUS_NOT_FOUND;
        resp->valid = TRUE;
        break;
    }

    default:
        resp->status = STATUS_INVALID_PARAMETER;
        resp->valid = FALSE;
        break;
    }

    req->completed = TRUE;
    req->status = resp->status;
    g_pp_context.request_pending = FALSE;
    g_pp_context.response_ready = TRUE;
}

FORCEINLINE ULONG_PTR get_cache_set_index(PVOID address) {
    return ((ULONG_PTR)address >> 6) & (CACHE_SETS - 1); 
}

FORCEINLINE ULONG64 measure_access_time_precise(PVOID address) {
    ULONG64 start, end;

    __try { 
        _mm_lfence();
        start = __rdtsc();
        _mm_lfence();     
        volatile UCHAR temp = *(volatile UCHAR*)address;
        _mm_lfence();
        end = __rdtsc();
        _mm_lfence();
        UNREFERENCED_PARAMETER(temp);
        return end - start;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1000; 
    }
}

NTSTATUS initialize_prime_probe_memory() {
    SIZE_T required_size = CACHE_SETS * PROBE_ADDRESSES_PER_SET * CACHE_LINE_SIZE * 2;

    g_pp_context.probe_memory_pool = ExAllocatePoolWithTag(
        NonPagedPool,
        required_size,
        'PrPr'
    );

    if (!g_pp_context.probe_memory_pool) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    g_pp_context.pool_size = required_size;
    RtlZeroMemory(g_pp_context.probe_memory_pool, required_size);

    UCHAR* base_addr = (UCHAR*)g_pp_context.probe_memory_pool;

    for (ULONG set = 0; set < CACHE_SETS; set++) {
        g_pp_context.sets[set].cache_set_index = set;

        for (ULONG addr_idx = 0; addr_idx < PROBE_ADDRESSES_PER_SET; addr_idx++) {
            
            ULONG_PTR offset = (set * CACHE_LINE_SIZE) +
                (addr_idx * CACHE_SETS * CACHE_LINE_SIZE);

            g_pp_context.sets[set].addresses[addr_idx] = base_addr + offset;
            g_pp_context.sets[set].baseline_times[addr_idx] = 0;
            g_pp_context.sets[set].probe_times[addr_idx] = 0;
        }
        g_pp_context.sets[set].evicted = FALSE;
    }

    return STATUS_SUCCESS;
}
VOID calibrate_timing_thresholds() {
    ULONG64 hit_times[100];
    ULONG64 miss_times[100];
    ULONG hit_count = 0, miss_count = 0;

    for (ULONG i = 0; i < 100 && hit_count < 100; i++) {
        PVOID addr = g_pp_context.sets[0].addresses[0];

        volatile UCHAR temp = *(volatile UCHAR*)addr;
        UNREFERENCED_PARAMETER(temp);

        ULONG64 time = measure_access_time_precise(addr);
        if (time < 500) { 
            hit_times[hit_count++] = time;
        }
    }
    for (ULONG i = 0; i < 100 && miss_count < 100; i++) {
        PVOID addr = g_pp_context.sets[1].addresses[0];

        _mm_clflush(addr);
        _mm_mfence();

        ULONG64 time = measure_access_time_precise(addr);
        if (time > 100) { 
            miss_times[miss_count++] = time;
        }
    }

    ULONG64 avg_hit = 0, avg_miss = 0;

    for (ULONG i = 0; i < hit_count; i++) {
        avg_hit += hit_times[i];
    }
    if (hit_count > 0) avg_hit /= hit_count;

    for (ULONG i = 0; i < miss_count; i++) {
        avg_miss += miss_times[i];
    }
    if (miss_count > 0) avg_miss /= miss_count;

    g_pp_context.calibration_threshold = (avg_hit + avg_miss) / 2;

    if (g_pp_context.calibration_threshold < 100) {
        g_pp_context.calibration_threshold = TIMING_THRESHOLD;
    }
}

VOID prime_cache_sets(ULONG data_bits) {
    for (ULONG set = 0; set < CACHE_SETS; set++) {
        BOOLEAN should_prime = FALSE;

        for (ULONG bit = 0; bit < MAX_DATA_BITS; bit++) {
            if (data_bits & (1UL << bit)) {
                ULONG target_set1 = (bit * 7 + 3) % CACHE_SETS;
                ULONG target_set2 = (bit * 11 + 5) % CACHE_SETS;
                ULONG target_set3 = (bit * 13 + 7) % CACHE_SETS;

                if (set == target_set1 || set == target_set2 || set == target_set3) {
                    should_prime = TRUE;
                    break;
                }
            }
        }

        if (should_prime) {
            for (ULONG addr_idx = 0; addr_idx < PROBE_ADDRESSES_PER_SET; addr_idx++) {
                __try {
                    volatile UCHAR temp = *(volatile UCHAR*)g_pp_context.sets[set].addresses[addr_idx];
                    UNREFERENCED_PARAMETER(temp);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    
                }
            }
        }
        else {
            for (ULONG addr_idx = 0; addr_idx < PROBE_ADDRESSES_PER_SET; addr_idx++) {
                __try {
                    _mm_clflush(g_pp_context.sets[set].addresses[addr_idx]);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    
                }
            }
        }
    }
    _mm_mfence();
}
ULONG probe_cache_sets() {
    ULONG decoded_data = 0;

    KeStallExecutionProcessor(10);

    for (ULONG set = 0; set < CACHE_SETS; set++) {
        ULONG64 total_time = 0;
        ULONG valid_measurements = 0;

        for (ULONG addr_idx = 0; addr_idx < PROBE_ADDRESSES_PER_SET; addr_idx++) {
            ULONG64 access_time = measure_access_time_precise(g_pp_context.sets[set].addresses[addr_idx]);

            if (access_time < 2000) { 
                total_time += access_time;
                valid_measurements++;
            }
        }
        if (valid_measurements > 0) {
            ULONG64 avg_time = total_time / valid_measurements;

            if (avg_time > g_pp_context.calibration_threshold) {
                g_pp_context.sets[set].evicted = TRUE;

                for (ULONG bit = 0; bit < MAX_DATA_BITS; bit++) {
                    ULONG target_set1 = (bit * 7 + 3) % CACHE_SETS;
                    ULONG target_set2 = (bit * 11 + 5) % CACHE_SETS;
                    ULONG target_set3 = (bit * 13 + 7) % CACHE_SETS;

                    if (set == target_set1 || set == target_set2 || set == target_set3) {
                        decoded_data |= (1UL << bit);
                        break;
                    }
                }
            }
            else {
                g_pp_context.sets[set].evicted = FALSE;
            }
        }
    }
    return decoded_data;
}
VOID encode_data_prime_probe(ULONG data) {
    if (!g_pp_context.initialized) return;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_cache_lock, &old_irql);

    g_pp_context.current_data = data;
    g_pp_context.sequence_number++;

    prime_cache_sets(data);

    KeReleaseSpinLock(&g_cache_lock, old_irql);
}

ULONG decode_data_prime_probe() {
    if (!g_pp_context.initialized) return 0;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_cache_lock, &old_irql);

    ULONG decoded_data = probe_cache_sets();

    KeReleaseSpinLock(&g_cache_lock, old_irql);

    return decoded_data;
}

VOID cache_communication_dpc(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    if (!g_pp_context.initialized) return;

    if (g_pp_context.request_pending) {
        process_cache_rw_request();
    }

    ULONG data_to_send = (ULONG)KeQueryUnbiasedInterruptTime() & 0xFFFF;

    if (g_pp_context.response_ready) {
        data_to_send |= 0x80000000; 
        if (NT_SUCCESS(g_pp_context.last_response.status)) {
            data_to_send |= 0x40000000; 
        }
    }
    encode_data_prime_probe(data_to_send);
    ULONG received_data = decode_data_prime_probe();
    if (received_data & 0x10000000) { 
        ULONG op_type = (received_data >> 24) & 0xF;
        ULONG proc_id = (received_data >> 16) & 0xFF;

        // simple request
        if (!g_pp_context.request_pending && op_type > 0 && op_type <= 4) {
            g_pp_context.pending_request.operation_type = op_type;
            g_pp_context.pending_request.process_id = proc_id;
            g_pp_context.pending_request.target_address = 0x400000; 
            g_pp_context.pending_request.size = sizeof(ULONG64);
            g_pp_context.pending_request.data_value = received_data & 0xFFFF;
            g_pp_context.pending_request.completed = FALSE;
            g_pp_context.request_pending = TRUE;
            g_pp_context.response_ready = FALSE;
        }
    }
    if (g_timer_initialized) {
        LARGE_INTEGER due_time;
        due_time.QuadPart = -10000LL * 100; 
        KeSetTimer(&g_communication_timer, due_time, &g_communication_dpc);
    }
}
VOID cleanup_prime_probe_memory() {
    if (g_pp_context.probe_memory_pool) {
        ExFreePoolWithTag(g_pp_context.probe_memory_pool, 'PrPr');
        g_pp_context.probe_memory_pool = NULL;
    }
    RtlZeroMemory(&g_pp_context, sizeof(g_pp_context));
}
// dummy I/O handler
NTSTATUS __forceinline x_cache_io_handler(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS __forceinline x_cache_dispatch(PDEVICE_OBJECT dev, PIRP irp) {
    UNREFERENCED_PARAMETER(dev);

    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

void __forceinline x_cache_unload(PDRIVER_OBJECT drv) {
    if (g_timer_initialized) {
        KeCancelTimer(&g_communication_timer);
        g_timer_initialized = FALSE;
    }

    cleanup_prime_probe_memory();

    if (drv->DeviceObject) {
        IoDeleteSymbolicLink(&g_cache_sname);
        IoDeleteDevice(drv->DeviceObject);
    }
}

NTSTATUS create_driver(NTSTATUS(*entry_point)(DRIVER_OBJECT*, UNICODE_STRING*))
{
    DRIVER_OBJECT* driver_object = nullptr;
    wchar_t name_buffer[100] = { 0 };
    UNICODE_STRING driver_name;
    OBJECT_ATTRIBUTES obj_attributes;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    auto timestamp = KeQueryUnbiasedInterruptTime();
    int pos = 0;
    name_buffer[pos++] = L'\\';
    name_buffer[pos++] = L'D';
    name_buffer[pos++] = L'r';
    name_buffer[pos++] = L'i';
    name_buffer[pos++] = L'v';
    name_buffer[pos++] = L'e';
    name_buffer[pos++] = L'r';
    name_buffer[pos++] = L'\\';

    for (int i = 0; i < 8; i++) {
        int digit = (timestamp >> (28 - i * 4)) & 0xF;
        name_buffer[pos++] = digit < 10 ? (L'0' + digit) : (L'A' + digit - 10);
    }

    auto name_length = static_cast<UINT16>(pos);
    if (name_length == 0)
        return STATUS_INVALID_PARAMETER;

    driver_name.Length = name_length * sizeof(wchar_t);
    driver_name.MaximumLength = driver_name.Length + sizeof(wchar_t);
    driver_name.Buffer = name_buffer;

    InitializeObjectAttributes(
        &obj_attributes,
        &driver_name,
        0x00000240,
        nullptr,
        nullptr
    );

    auto obj_size = sizeof(DRIVER_OBJECT) + sizeof(void*) * 10;

    void* driver_obj_ptr = nullptr;
    status = ObCreateObject(
        KernelMode,
        *IoDriverObjectType,
        &obj_attributes,
        KernelMode,
        nullptr,
        obj_size,
        0,
        0,
        &driver_obj_ptr
    );
    if (status != STATUS_SUCCESS || !driver_obj_ptr)
        return status;

    driver_object = static_cast<DRIVER_OBJECT*>(driver_obj_ptr);

    RtlZeroMemory(driver_object, obj_size);
    driver_object->Type = 4;
    driver_object->Size = sizeof(DRIVER_OBJECT);
    driver_object->Flags = 2;

    driver_object->DriverExtension = reinterpret_cast<PDRIVER_EXTENSION>(reinterpret_cast<UINT8*>(driver_object) + sizeof(DRIVER_OBJECT));

    if (!driver_object->DriverExtension) {
        ObMakeTemporaryObject(driver_object);
        ObDereferenceObject(driver_object);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int i = 0; i <= 0x1B; i++)
        driver_object->MajorFunction[i] = nullptr;

    status = entry_point(driver_object, nullptr);
    ObMakeTemporaryObject(driver_object);
    ObDereferenceObject(driver_object);
    return status;
}

NTSTATUS __forceinline x_cache_init(PDRIVER_OBJECT drv, PUNICODE_STRING reg) {
    UNREFERENCED_PARAMETER(reg);
    NTSTATUS st = STATUS_SUCCESS;
    PDEVICE_OBJECT dev = NULL;

    KeInitializeSpinLock(&g_cache_lock);

    RtlInitUnicodeString(&g_cache_dname, L"\\Device\\{cachesidechannel2}");
    RtlInitUnicodeString(&g_cache_sname, L"\\DosDevices\\{cachesidechannel2}");

    st = IoCreateDevice(drv, 0, &g_cache_dname, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev);
    if (!NT_SUCCESS(st))
        return st;

    st = IoCreateSymbolicLink(&g_cache_sname, &g_cache_dname);
    if (!NT_SUCCESS(st)) {
        IoDeleteDevice(dev);
        return st;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
        drv->MajorFunction[i] = &x_cache_dispatch;

    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &x_cache_io_handler;
    drv->DriverUnload = &x_cache_unload;

    dev->Flags |= DO_BUFFERED_IO;
    dev->Flags &= ~DO_DEVICE_INITIALIZING;

    st = initialize_prime_probe_memory();
    if (!NT_SUCCESS(st)) {
        IoDeleteSymbolicLink(&g_cache_sname);
        IoDeleteDevice(dev);
        return st;
    }

    calibrate_timing_thresholds();

    RtlZeroMemory(&g_pp_context.pending_request, sizeof(CACHE_RW_REQUEST));
    RtlZeroMemory(&g_pp_context.last_response, sizeof(CACHE_RW_RESPONSE));
    g_pp_context.request_pending = FALSE;
    g_pp_context.response_ready = FALSE;
    g_pp_context.initialized = TRUE;
    KeInitializeTimer(&g_communication_timer);
    KeInitializeDpc(&g_communication_dpc, cache_communication_dpc, NULL);

    LARGE_INTEGER due_time;
    due_time.QuadPart = -10000LL * 200;
    KeSetTimer(&g_communication_timer, due_time, &g_communication_dpc);
    g_timer_initialized = TRUE;

    return st;
}
extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = create_driver(&x_cache_init);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    return status;
}
