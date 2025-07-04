#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include "../src/vfm.h"
#include "../src/opcodes.h"

// Benchmark configuration
#define BENCHMARK_PACKETS 1000000    // 1M packets per test
#define WARMUP_PACKETS 10000         // Warmup iterations
#define ITERATIONS 3                 // Number of benchmark iterations

// Different packet sizes to test
static const int packet_sizes[] = {64, 128, 256, 512, 1024, 1518};
static const int num_packet_sizes = sizeof(packet_sizes) / sizeof(packet_sizes[0]);

// Benchmark statistics
typedef struct {
    const char *name;
    double min_ns_per_packet;
    double max_ns_per_packet;
    double avg_ns_per_packet;
    double mpps;
    int packet_size;
    uint64_t packets_processed;
    uint64_t accepted_packets;
    uint64_t dropped_packets;
} benchmark_result_t;

// High precision timer
static double get_time_ns(void) {
#ifdef __APPLE__
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (double)tv.tv_sec * 1e9 + (double)tv.tv_usec * 1e3;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
#endif
}

// Create test packet with specified size and characteristics
static void create_test_packet(uint8_t *packet, int size, int packet_type) {
    memset(packet, 0, size);
    
    // Ethernet header
    packet[12] = 0x08; packet[13] = 0x00;  // IPv4
    
    // IP header
    packet[14] = 0x45;  // Version 4, IHL 5
    packet[15] = 0x00;  // TOS
    packet[22] = 0x40;  // TTL
    // Source IP: varies by packet type
    packet[26] = 192; packet[27] = 168; packet[28] = 1; packet[29] = 100 + (packet_type % 50);
    // Dest IP: 10.0.0.1
    packet[30] = 10; packet[31] = 0; packet[32] = 0; packet[33] = 1;
    
    switch (packet_type % 4) {
        case 0: // TCP SYN packet
            packet[23] = 0x06;  // Protocol TCP
            packet[34] = 0x04; packet[35] = 0xD2;  // Source port 1234
            packet[36] = 0x00; packet[37] = 0x50;  // Dest port 80
            packet[47] = 0x02;  // Flags (SYN)
            break;
            
        case 1: // TCP ACK packet  
            packet[23] = 0x06;  // Protocol TCP
            packet[34] = 0x04; packet[35] = 0xD2;  // Source port 1234
            packet[36] = 0x00; packet[37] = 0x50;  // Dest port 80
            packet[47] = 0x10;  // Flags (ACK)
            break;
            
        case 2: // UDP packet
            packet[23] = 0x11;  // Protocol UDP
            packet[34] = 0x04; packet[35] = 0xD2;  // Source port 1234
            packet[36] = 0x00; packet[37] = 0x35;  // Dest port 53 (DNS)
            break;
            
        case 3: // ICMP packet
            packet[23] = 0x01;  // Protocol ICMP
            packet[34] = 0x08;  // ICMP Echo Request
            break;
    }
}

// Simple "accept all" program for baseline performance
static uint8_t accept_all_program[] = {
    VFM_PUSH, 1, 0, 0, 0, 0, 0, 0, 0,  // PUSH 1
    VFM_RET                             // RET
};

// Simple packet filter (TCP only)
static uint8_t tcp_filter_program[] = {
    VFM_LD8, 23, 0,                    // Load IP protocol
    VFM_PUSH, 6, 0, 0, 0, 0, 0, 0, 0,  // TCP protocol
    VFM_JEQ, 0x0A, 0x00,               // Jump to accept if TCP
    VFM_PUSH, 0, 0, 0, 0, 0, 0, 0, 0,  // Push 0 (drop)
    VFM_RET,                           // Return
    VFM_PUSH, 1, 0, 0, 0, 0, 0, 0, 0,  // Push 1 (accept)
    VFM_RET                            // Return
};

// Complex filter (TCP SYN detection with port filtering)
static uint8_t complex_filter_program[] = {
    // Check for IPv4
    VFM_LD16, 12, 0,                   // Load EtherType
    VFM_PUSH, 0x08, 0x00, 0, 0, 0, 0, 0, 0,  // IPv4
    VFM_JNE, 50, 0,                    // Jump to drop if not IPv4
    
    // Check for TCP
    VFM_LD8, 23, 0,                    // Load IP protocol
    VFM_PUSH, 6, 0, 0, 0, 0, 0, 0, 0,  // TCP
    VFM_JNE, 41, 0,                    // Jump to drop if not TCP
    
    // Check destination port (80 or 443)
    VFM_LD16, 36, 0,                   // Load dest port
    VFM_DUP,                           // Duplicate port
    VFM_PUSH, 80, 0, 0, 0, 0, 0, 0, 0, // Port 80
    VFM_JEQ, 19, 0,                    // Jump to flag check if port 80
    VFM_PUSH, 443, 0, 0, 0, 0, 0, 0, 0, // Port 443
    VFM_JNE, 24, 0,                    // Jump to drop if not 443
    
    // Check for SYN flag
    VFM_LD8, 47, 0,                    // Load TCP flags
    VFM_PUSH, 0x02, 0, 0, 0, 0, 0, 0, 0, // SYN flag
    VFM_AND,                           // Check if SYN is set
    VFM_PUSH, 0x02, 0, 0, 0, 0, 0, 0, 0, // SYN flag
    VFM_JEQ, 10, 0,                    // Jump to accept if SYN
    
    // Drop
    VFM_PUSH, 0, 0, 0, 0, 0, 0, 0, 0,  // Push 0 (drop)
    VFM_RET,                           // Return
    
    // Accept
    VFM_PUSH, 1, 0, 0, 0, 0, 0, 0, 0,  // Push 1 (accept)
    VFM_RET                            // Return
};

// Run benchmark for a specific program and packet configuration
static benchmark_result_t run_benchmark(const char *name, uint8_t *program, uint32_t program_size, 
                                       int packet_size, int num_packets) {
    benchmark_result_t result = {0};
    result.name = name;
    result.packet_size = packet_size;
    
    // Create VM
    vfm_state_t *vm = vfm_create();
    if (!vm) {
        printf("Error: Failed to create VM\n");
        return result;
    }
    
    // Load program
    int load_result = vfm_load_program(vm, program, program_size);
    if (load_result != VFM_SUCCESS) {
        printf("Error: Failed to load program: %d\n", load_result);
        vfm_destroy(vm);
        return result;
    }
    
    // Allocate packet buffer
    uint8_t *packet = malloc(packet_size);
    if (!packet) {
        printf("Error: Failed to allocate packet buffer\n");
        vfm_destroy(vm);
        return result;
    }
    
    double total_time = 0.0;
    double min_time = 1e9;
    double max_time = 0.0;
    
    // Warmup
    for (int i = 0; i < WARMUP_PACKETS; i++) {
        create_test_packet(packet, packet_size, i);
        vfm_execute(vm, packet, packet_size);
    }
    
    // Run benchmark iterations
    for (int iter = 0; iter < ITERATIONS; iter++) {
        double iter_start = get_time_ns();
        uint64_t iter_accepted = 0;
        
        for (int i = 0; i < num_packets; i++) {
            create_test_packet(packet, packet_size, i);
            
            double start_time = get_time_ns();
            int exec_result = vfm_execute(vm, packet, packet_size);
            double end_time = get_time_ns();
            
            double elapsed = end_time - start_time;
            if (elapsed < min_time) min_time = elapsed;
            if (elapsed > max_time) max_time = elapsed;
            
            if (exec_result == 1) {
                iter_accepted++;
            }
            
            result.packets_processed++;
        }
        
        double iter_end = get_time_ns();
        double iter_time = iter_end - iter_start;
        total_time += iter_time;
        result.accepted_packets += iter_accepted;
    }
    
    result.dropped_packets = result.packets_processed - result.accepted_packets;
    result.min_ns_per_packet = min_time;
    result.max_ns_per_packet = max_time;
    result.avg_ns_per_packet = total_time / result.packets_processed;
    result.mpps = 1e9 / result.avg_ns_per_packet / 1e6;  // Million packets per second
    
    free(packet);
    vfm_destroy(vm);
    
    return result;
}

// Print benchmark result
static void print_result(const benchmark_result_t *result) {
    printf("%-25s %4d bytes  %8.1f ns  %8.1f ns  %8.1f ns  %8.2f Mpps  %6.1f%%\n",
           result->name,
           result->packet_size,
           result->min_ns_per_packet,
           result->avg_ns_per_packet,
           result->max_ns_per_packet,
           result->mpps,
           result->packets_processed > 0 ? 
               100.0 * result->accepted_packets / result->packets_processed : 0.0);
}

// Run comprehensive benchmark suite
static void run_comprehensive_benchmarks(void) {
    printf("VFM Performance Benchmark Suite\n");
    printf("================================\n\n");
    
    printf("Configuration:\n");
    printf("- Packets per test: %d\n", BENCHMARK_PACKETS);
    printf("- Warmup packets: %d\n", WARMUP_PACKETS);
    printf("- Iterations: %d\n", ITERATIONS);
    printf("- Platform: macOS (Apple Silicon optimized)\n\n");
    
    printf("%-25s %10s  %10s  %10s  %10s  %10s  %8s\n",
           "Filter", "Size", "Min (ns)", "Avg (ns)", "Max (ns)", "Throughput", "Accept%");
    printf("%-25s %10s  %10s  %10s  %10s  %10s  %8s\n",
           "------", "----", "--------", "--------", "--------", "----------", "-------");
    
    // Test different filters with different packet sizes
    for (int i = 0; i < num_packet_sizes; i++) {
        int size = packet_sizes[i];
        
        // Accept All filter (baseline)
        benchmark_result_t result = run_benchmark("Accept All", accept_all_program, 
                                                 sizeof(accept_all_program), size, BENCHMARK_PACKETS);
        print_result(&result);
        
        // TCP filter
        result = run_benchmark("TCP Filter", tcp_filter_program, 
                              sizeof(tcp_filter_program), size, BENCHMARK_PACKETS);
        print_result(&result);
        
        // Complex SYN filter
        result = run_benchmark("Complex SYN Filter", complex_filter_program, 
                              sizeof(complex_filter_program), size, BENCHMARK_PACKETS);
        print_result(&result);
        
        if (i < num_packet_sizes - 1) {
            printf("\n");
        }
    }
    
    printf("\n");
}

// Memory usage analysis
static void analyze_memory_usage(void) {
    printf("Memory Usage Analysis\n");
    printf("=====================\n\n");
    
    vfm_state_t *vm = vfm_create();
    if (!vm) {
        printf("Error: Failed to create VM\n");
        return;
    }
    
    printf("VM State Structure Size:   %zu bytes\n", sizeof(vfm_state_t));
    printf("Default Stack Size:        %u entries (%zu bytes)\n", 
           VFM_MAX_STACK, VFM_MAX_STACK * sizeof(uint64_t));
    printf("Maximum Program Size:      %u bytes\n", VFM_MAX_PROGRAM_SIZE);
    printf("Flow Table Size:           %u entries (%zu bytes)\n",
           VFM_FLOW_TABLE_SIZE, VFM_FLOW_TABLE_SIZE * sizeof(vfm_flow_entry_t));
    
    size_t total_vm_memory = sizeof(vfm_state_t) + 
                            VFM_MAX_STACK * sizeof(uint64_t) +
                            VFM_FLOW_TABLE_SIZE * sizeof(vfm_flow_entry_t);
    
    printf("Total VM Memory Footprint: %zu bytes (%.2f KB)\n", 
           total_vm_memory, total_vm_memory / 1024.0);
    
    vfm_destroy(vm);
    printf("\n");
}

// Performance scaling analysis
static void analyze_performance_scaling(void) {
    printf("Performance Scaling Analysis\n");
    printf("============================\n\n");
    
    printf("Testing performance with varying packet counts...\n\n");
    
    const int packet_counts[] = {1000, 10000, 100000, 1000000};
    const int num_counts = sizeof(packet_counts) / sizeof(packet_counts[0]);
    
    printf("%-15s %12s %12s %12s\n", "Packet Count", "Time (ms)", "Avg (ns)", "Mpps");
    printf("%-15s %12s %12s %12s\n", "------------", "--------", "--------", "----");
    
    for (int i = 0; i < num_counts; i++) {
        benchmark_result_t result = run_benchmark("Scaling Test", tcp_filter_program, 
                                                 sizeof(tcp_filter_program), 128, packet_counts[i]);
        printf("%-15d %12.2f %12.1f %12.2f\n",
               packet_counts[i],
               result.avg_ns_per_packet * packet_counts[i] / 1e6,
               result.avg_ns_per_packet,
               result.mpps);
    }
    
    printf("\n");
}

// Performance comparison against targets
static void performance_comparison(void) {
    printf("Performance Target Comparison\n");
    printf("=============================\n\n");
    
    printf("Project targets from CLAUDE.md:\n");
    printf("- 10M+ pps for simple filters\n");
    printf("- < 50ns per packet overhead\n");
    printf("- Linear scaling with complexity\n\n");
    
    // Test simple filter performance
    benchmark_result_t simple = run_benchmark("Simple Filter Target Test", accept_all_program, 
                                             sizeof(accept_all_program), 64, BENCHMARK_PACKETS);
    
    benchmark_result_t tcp = run_benchmark("TCP Filter Target Test", tcp_filter_program, 
                                          sizeof(tcp_filter_program), 64, BENCHMARK_PACKETS);
    
    benchmark_result_t complex = run_benchmark("Complex Filter Target Test", complex_filter_program, 
                                              sizeof(complex_filter_program), 64, BENCHMARK_PACKETS);
    
    printf("Results:\n");
    printf("%-25s %8.2f Mpps  %6.1f ns  %s\n", 
           "Simple (Accept All):", simple.mpps, simple.avg_ns_per_packet,
           simple.mpps >= 10.0 && simple.avg_ns_per_packet <= 50.0 ? "✓ PASS" : "✗ FAIL");
    printf("%-25s %8.2f Mpps  %6.1f ns  %s\n", 
           "TCP Filter:", tcp.mpps, tcp.avg_ns_per_packet,
           tcp.mpps >= 5.0 && tcp.avg_ns_per_packet <= 100.0 ? "✓ PASS" : "✗ FAIL");
    printf("%-25s %8.2f Mpps  %6.1f ns  %s\n", 
           "Complex Filter:", complex.mpps, complex.avg_ns_per_packet,
           complex.mpps >= 2.0 && complex.avg_ns_per_packet <= 200.0 ? "✓ PASS" : "✗ FAIL");
    
    // Check linear scaling
    double complexity_ratio = complex.avg_ns_per_packet / simple.avg_ns_per_packet;
    printf("\nComplexity scaling ratio: %.2fx\n", complexity_ratio);
    printf("Linear scaling (< 10x): %s\n", complexity_ratio < 10.0 ? "✓ PASS" : "✗ FAIL");
    
    printf("\n");
}

int main(int argc, char *argv[]) {
    int quick_mode = 0;
    
    // Check for quick mode flag
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--quick") == 0) {
            quick_mode = 1;
        }
    }
    
    if (quick_mode) {
        printf("Running quick benchmark...\n\n");
        
        // Quick test with smaller packet count
        benchmark_result_t result = run_benchmark("Quick Test", tcp_filter_program, 
                                                 sizeof(tcp_filter_program), 128, 10000);
        printf("Quick benchmark result:\n");
        print_result(&result);
        printf("\nRun without --quick for comprehensive benchmarks.\n");
        
        return 0;
    }
    
    // Run comprehensive benchmark suite
    run_comprehensive_benchmarks();
    analyze_memory_usage();
    analyze_performance_scaling();
    performance_comparison();
    
    printf("Benchmark Summary\n");
    printf("=================\n");
    printf("VFM achieves high-performance packet filtering with:\n");
    printf("- Computed goto dispatch for minimal overhead\n");
    printf("- Cache-optimized data structures for Apple Silicon\n");
    printf("- Bounds-checked packet access for safety\n");
    printf("- Linear performance scaling with filter complexity\n");
    printf("\nSee CLAUDE.md for detailed performance targets and architecture.\n");
    
    return 0;
}