// THIS WILL STILL PICK UP CACHE ACTIVITY EVEN WHEN DRIVER IS NOT LOADED

// with driver loaded you will see real patterns

#include <windows.h>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <intrin.h>
#include <algorithm>

#define CACHE_LINE_SIZE 64
#define CACHE_SETS 64
#define PROBE_ADDRESSES_PER_SET 16
#define TIMING_THRESHOLD 200
#define MAX_DATA_BITS 32
#define COMMUNICATION_ROUNDS 4

#define RW_OP_READ 1
#define RW_OP_WRITE 2
#define RW_OP_GET_BASE 3
#define RW_OP_GET_PEB 4

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

typedef struct _USER_PROBE_SET {
    void* addresses[PROBE_ADDRESSES_PER_SET];
    ULONG64 baseline_times[PROBE_ADDRESSES_PER_SET];
    ULONG64 probe_times[PROBE_ADDRESSES_PER_SET];
    BOOLEAN evicted;
    ULONG cache_set_index;
} USER_PROBE_SET, * PUSER_PROBE_SET;

typedef struct _USER_PRIME_PROBE_CONTEXT {
    USER_PROBE_SET sets[CACHE_SETS];
    void* probe_memory_pool;
    SIZE_T pool_size;
    ULONG current_data;
    ULONG sequence_number;
    BOOLEAN initialized;
    ULONG64 calibration_threshold;

    CACHE_RW_REQUEST pending_request;
    CACHE_RW_RESPONSE last_response;
    BOOLEAN request_pending;
    BOOLEAN response_ready;
} USER_PRIME_PROBE_CONTEXT, * PUSER_PRIME_PROBE_CONTEXT;

USER_PRIME_PROBE_CONTEXT g_user_pp_context = { 0 };
volatile BOOLEAN g_communication_active = FALSE;
BOOLEAN g_driver_detected = FALSE;

BOOLEAN check_cache_driver_loaded() {
    std::cout << "Checking for cache side-channel driver..." << std::endl;

    HANDLE hDevice = CreateFileW(
        L"\\\\.\\{cachesidechannel2}",
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice != INVALID_HANDLE_VALUE) {
        std::cout << "Cache side-channel driver detected and accessible!" << std::endl;
        CloseHandle(hDevice);
        return TRUE;
    }

    DWORD error = GetLastError();
    std::cout << "Cache side-channel driver not found (Error: " << error << ")" << std::endl;
    return FALSE;
}

__forceinline ULONG64 measure_access_time_precise(void* address) {
    ULONG64 start, end;
    __try {
        _mm_lfence();
        start = __rdtsc();
        _mm_lfence();

        volatile UCHAR temp = *(volatile UCHAR*)address;

        _mm_lfence();
        end = __rdtsc();
        _mm_lfence();

        return end - start;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return 1000;
    }
}

BOOLEAN initialize_user_prime_probe_memory() {
    SIZE_T required_size = CACHE_SETS * PROBE_ADDRESSES_PER_SET * CACHE_LINE_SIZE * 2;

    g_user_pp_context.probe_memory_pool = VirtualAlloc(
        NULL,
        required_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    if (!g_user_pp_context.probe_memory_pool) {
        return FALSE;
    }

    g_user_pp_context.pool_size = required_size;

    memset(g_user_pp_context.probe_memory_pool, 0, required_size);
    UCHAR* base_addr = (UCHAR*)g_user_pp_context.probe_memory_pool;
    for (ULONG set = 0; set < CACHE_SETS; set++) {
        g_user_pp_context.sets[set].cache_set_index = set;

        for (ULONG addr_idx = 0; addr_idx < PROBE_ADDRESSES_PER_SET; addr_idx++) {
            ULONG_PTR offset = (set * CACHE_LINE_SIZE) +
                (addr_idx * CACHE_SETS * CACHE_LINE_SIZE);
            g_user_pp_context.sets[set].addresses[addr_idx] = base_addr + offset;
            g_user_pp_context.sets[set].baseline_times[addr_idx] = 0;
            g_user_pp_context.sets[set].probe_times[addr_idx] = 0;
        }
        g_user_pp_context.sets[set].evicted = FALSE;
    }
    return TRUE;
}

void calibrate_user_timing_thresholds() {
    std::cout << "Starting timing calibration..." << std::endl;
    std::vector<ULONG64> hit_times;
    std::vector<ULONG64> miss_times;
    for (int round = 0; round < 5; round++) {
        std::cout << "Calibration round " << (round + 1) << "/5..." << std::endl;

        for (ULONG i = 0; i < 200; i++) {
            void* addr = g_user_pp_context.sets[i % CACHE_SETS].addresses[0];

            for (int warm = 0; warm < 3; warm++) {
                volatile UCHAR temp = *(volatile UCHAR*)addr;
            }
            ULONG64 time = measure_access_time_precise(addr);
            if (time < 1000 && time > 10) {
                hit_times.push_back(time);
            }
        }
        for (ULONG i = 0; i < 200; i++) {
            void* addr = g_user_pp_context.sets[i % CACHE_SETS].addresses[1];

            _mm_clflush(addr);
            _mm_mfence();

            for (int j = 0; j < 10; j++) {
                void* other_addr = g_user_pp_context.sets[(i + j) % CACHE_SETS].addresses[2];
                volatile UCHAR temp = *(volatile UCHAR*)other_addr;
            }

            ULONG64 time = measure_access_time_precise(addr);
            if (time < 2000 && time > 50) {
                miss_times.push_back(time);
            }
        }

        Sleep(100);
    }

    if (hit_times.empty() || miss_times.empty()) {
        std::cout << "Calibration failed - using default threshold" << std::endl;
        g_user_pp_context.calibration_threshold = TIMING_THRESHOLD;
        return;
    }

    std::sort(hit_times.begin(), hit_times.end());
    std::sort(miss_times.begin(), miss_times.end());

    ULONG64 hit_p90 = hit_times[hit_times.size() * 9 / 10];
    ULONG64 hit_median = hit_times[hit_times.size() / 2];
    ULONG64 miss_p10 = miss_times[miss_times.size() / 10];
    ULONG64 miss_median = miss_times[miss_times.size() / 2];

    ULONG64 avg_hit = 0, avg_miss = 0;
    for (auto time : hit_times) avg_hit += time;
    avg_hit /= hit_times.size();

    for (auto time : miss_times) avg_miss += time;
    avg_miss /= miss_times.size();

    std::cout << "Calibration Statistics:" << std::endl;
    std::cout << "   Hit times  - Avg: " << avg_hit << ", Median: " << hit_median << ", P90: " << hit_p90 << std::endl;
    std::cout << "   Miss times - Avg: " << avg_miss << ", Median: " << miss_median << ", P10: " << miss_p10 << std::endl;

    ULONG64 threshold1 = (avg_hit + avg_miss) / 2;
    ULONG64 threshold2 = (hit_p90 + miss_p10) / 2;
    ULONG64 threshold3 = hit_median + (miss_median - hit_median) / 3;

    g_user_pp_context.calibration_threshold = threshold2;

    if (g_driver_detected) {
        g_user_pp_context.calibration_threshold = (ULONG64)(g_user_pp_context.calibration_threshold * 0.8);
        std::cout << " Adjusted threshold for driver presence" << std::endl;
    }

    if (g_user_pp_context.calibration_threshold < 80) {
        g_user_pp_context.calibration_threshold = 80;
    }
    else if (g_user_pp_context.calibration_threshold > 800) {
        g_user_pp_context.calibration_threshold = 800;
    }

    std::cout << "Final calibration threshold: " << g_user_pp_context.calibration_threshold << " cycles" << std::endl;
    std::cout << "Separation ratio: " << ((double)avg_miss / avg_hit) << ":1" << std::endl;
}

void prime_cache_sets_user(ULONG data_bits) {
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
                    volatile UCHAR temp = *(volatile UCHAR*)g_user_pp_context.sets[set].addresses[addr_idx];
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {

                }
            }
        }
        else {

            for (ULONG addr_idx = 0; addr_idx < PROBE_ADDRESSES_PER_SET; addr_idx++) {
                __try {
                    _mm_clflush(g_user_pp_context.sets[set].addresses[addr_idx]);
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {

                }
            }
        }
    }
    _mm_mfence();
}

ULONG probe_cache_sets_user() {
    ULONG decoded_data = 0;
    Sleep(1);

    for (ULONG set = 0; set < CACHE_SETS; set++) {
        ULONG64 total_time = 0;
        ULONG valid_measurements = 0;


        for (ULONG addr_idx = 0; addr_idx < PROBE_ADDRESSES_PER_SET; addr_idx++) {
            ULONG64 access_time = measure_access_time_precise(g_user_pp_context.sets[set].addresses[addr_idx]);

            if (access_time < 2000) {
                total_time += access_time;
                valid_measurements++;
            }
        }

        if (valid_measurements > 0) {
            ULONG64 avg_time = total_time / valid_measurements;

            if (avg_time > g_user_pp_context.calibration_threshold) {
                g_user_pp_context.sets[set].evicted = TRUE;

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
                g_user_pp_context.sets[set].evicted = FALSE;
            }
        }
    }

    return decoded_data;
}

void send_rw_request_cache(ULONG operation_type, ULONG process_id, ULONG64 target_address, ULONG64 data_value) {

    ULONG request_data = 0x10000000;
    request_data |= (operation_type & 0xF) << 24;
    request_data |= (process_id & 0xFF) << 16;
    request_data |= (data_value & 0xFFFF);

    std::cout << "Sending R/W request via cache side-channel:" << std::endl;
    std::cout << "Operation: " << operation_type << ", PID: " << process_id
        << ", Data: 0x" << std::hex << request_data << std::dec << std::endl;

    for (int i = 0; i < 3; i++) {
        prime_cache_sets_user(request_data);
        Sleep(10);
    }
    g_user_pp_context.pending_request.operation_type = operation_type;
    g_user_pp_context.pending_request.process_id = process_id;
    g_user_pp_context.pending_request.target_address = target_address;
    g_user_pp_context.pending_request.data_value = data_value;
    g_user_pp_context.pending_request.completed = FALSE;
    g_user_pp_context.request_pending = TRUE;
    g_user_pp_context.response_ready = FALSE;
}

BOOLEAN receive_rw_response_cache(CACHE_RW_RESPONSE* response) {
    if (!response) return FALSE;

    ULONG received_data = probe_cache_sets_user();

    if (received_data != 0) {
        std::cout << "Raw received data: 0x" << std::hex << received_data << std::dec << std::endl;
    }

    if (received_data & 0x80000000) {
        std::cout << "Received response via cache side-channel - Data: 0x"
            << std::hex << received_data << std::dec << std::endl;

        response->valid = TRUE;
        response->status = (received_data & 0x40000000) ? 0 : 0xC0000001; // STATUS_SUCCESS or UNSUCCESSFUL
        response->data_value = received_data & 0xFFFF;
        response->base_address = response->data_value;

        g_user_pp_context.response_ready = TRUE;
        return TRUE;
    }

    return FALSE;
}

// Communication thread function
void communication_thread() {
    std::cout << "Cache side-channel communication thread started" << std::endl;

    while (g_communication_active) {
        CACHE_RW_RESPONSE response = { 0 };
        if (receive_rw_response_cache(&response)) {
            g_user_pp_context.last_response = response;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    }

    std::cout << "Cache side-channel communication thread stopped" << std::endl;
}

void test_rw_operations() {
    DWORD current_pid = GetCurrentProcessId();

    std::cout << "\n=== Testing R/W Operations via Cache Side-Channel ===" << std::endl;
    std::cout << "Current Process ID: " << current_pid << std::endl;

    if (!g_driver_detected) {
        std::cout << "Warning: Driver not detected - responses may not be received" << std::endl;
    }

    std::cout << "\nTesting GET_BASE operation..." << std::endl;
    send_rw_request_cache(RW_OP_GET_BASE, current_pid, 0, 0);

    for (int i = 0; i < 50; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (g_user_pp_context.response_ready) {
            std::cout << "Base address response: 0x" << std::hex
                << g_user_pp_context.last_response.base_address << std::dec
                << " (Status: " << g_user_pp_context.last_response.status << ")" << std::endl;
            g_user_pp_context.response_ready = FALSE;
            break;
        }
        if (i % 10 == 0) {
            std::cout << "Waiting for response... (" << (i / 10 + 1) << "/5)" << std::endl;
        }
    }

    std::cout << "Testing GET_PEB operation..." << std::endl;
    send_rw_request_cache(RW_OP_GET_PEB, current_pid, 0, 0);

    for (int i = 0; i < 50; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (g_user_pp_context.response_ready) {
            std::cout << "PEB address response: 0x" << std::hex
                << g_user_pp_context.last_response.base_address << std::dec
                << " (Status: " << g_user_pp_context.last_response.status << ")" << std::endl;
            g_user_pp_context.response_ready = FALSE;
            break;
        }
        if (i % 10 == 0) {
            std::cout << "Waiting for response... (" << (i / 10 + 1) << "/5)" << std::endl;
        }
    }

    std::cout << "Testing READ operation..." << std::endl;
    ULONG64 test_address = (ULONG64)&current_pid; // Read PID variable
    std::cout << "   Target address: 0x" << std::hex << test_address << std::dec << std::endl;
    send_rw_request_cache(RW_OP_READ, current_pid, test_address, 0);

    for (int i = 0; i < 50; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (g_user_pp_context.response_ready) {
            std::cout << "Read response: 0x" << std::hex
                << g_user_pp_context.last_response.data_value << std::dec
                << " (Status: " << g_user_pp_context.last_response.status << ")" << std::endl;
            g_user_pp_context.response_ready = FALSE;
            break;
        }
        if (i % 10 == 0) {
            std::cout << "Waiting for response... (" << (i / 10 + 1) << "/5)" << std::endl;
        }
    }

    std::cout << "Testing WRITE operation..." << std::endl;
    ULONG64 test_value = 0x12345678;
    ULONG64 write_target = (ULONG64)&test_value;
    std::cout << "Target address: 0x" << std::hex << write_target << std::dec << std::endl;
    std::cout << "Original value: 0x" << std::hex << test_value << std::dec << std::endl;
    send_rw_request_cache(RW_OP_WRITE, current_pid, write_target, 0xDEADBEEF);

    for (int i = 0; i < 50; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (g_user_pp_context.response_ready) {
            std::cout << "Write response: 0x" << std::hex
                << g_user_pp_context.last_response.data_value << std::dec
                << " (Status: " << g_user_pp_context.last_response.status << ")" << std::endl;
            std::cout << "Verification - test_value is now: 0x" << std::hex << test_value << std::dec << std::endl;
            g_user_pp_context.response_ready = FALSE;
            break;
        }
        if (i % 10 == 0) {
            std::cout << "Waiting for response... (" << (i / 10 + 1) << "/5)" << std::endl;
        }
    }
}

// Cleanup function
void cleanup_user_prime_probe() {
    if (g_user_pp_context.probe_memory_pool) {
        VirtualFree(g_user_pp_context.probe_memory_pool, 0, MEM_RELEASE);
        g_user_pp_context.probe_memory_pool = NULL;
    }

    memset(&g_user_pp_context, 0, sizeof(g_user_pp_context));
}

int main() {
    std::cout << "Cache Side-Channel R/W Test Application" << std::endl;
    std::cout << "===========================================" << std::endl;

    g_driver_detected = check_cache_driver_loaded();

    // Initialize Prime+Probe memory
    if (!initialize_user_prime_probe_memory()) {
        std::cout << "Failed to initialize Prime+Probe memory!" << std::endl;
        return -1;
    }
    std::cout << "Prime+Probe memory initialized successfully" << std::endl;

    calibrate_user_timing_thresholds();

    g_user_pp_context.initialized = TRUE;

    // start communication thread
    g_communication_active = TRUE;
    std::thread comm_thread(communication_thread);


    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // test R/W operations
    test_rw_operations();

    // keep running for a bit to observe communication
    std::cout << "Monitoring cache side-channel communication for 15 seconds..." << std::endl;
    for (int i = 0; i < 15; i++) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::cout << "." << std::flush;
    }
    std::cout << std::endl;

    g_communication_active = FALSE;
    if (comm_thread.joinable()) {
        comm_thread.join();
    }
    cleanup_user_prime_probe();

    std::cout << "\nCommunication Test completed. Press Enter to exit..." << std::endl;
    std::cin.get();

    return 0;
}
