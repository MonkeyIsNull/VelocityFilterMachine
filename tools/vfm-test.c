#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include "../src/vfm.h"

// Simple packet file format:
// Each packet consists of:
// - 2 bytes: packet length (little endian)
// - N bytes: packet data
// EOF indicates end of packets

typedef struct {
    uint64_t total_packets;
    uint64_t accepted_packets;
    uint64_t dropped_packets;
    uint64_t error_packets;
    double total_time_ns;
    double min_time_ns;
    double max_time_ns;
} test_stats_t;

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

// Load filter from binary file
static int load_filter(const char *filename, uint8_t **program, uint32_t *program_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open filter file '%s': %s\n", filename, strerror(errno));
        return -1;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (size <= 0 || size > VFM_MAX_PROGRAM_SIZE) {
        fprintf(stderr, "Error: Invalid filter file size: %ld bytes\n", size);
        fclose(file);
        return -1;
    }
    
    // Allocate and read program
    *program = malloc(size);
    if (!*program) {
        fprintf(stderr, "Error: Cannot allocate memory for filter\n");
        fclose(file);
        return -1;
    }
    
    size_t read_size = fread(*program, 1, size, file);
    fclose(file);
    
    if (read_size != (size_t)size) {
        fprintf(stderr, "Error: Failed to read filter file\n");
        free(*program);
        return -1;
    }
    
    *program_size = (uint32_t)size;
    return 0;
}

// Read next packet from file
static int read_packet(FILE *file, uint8_t *buffer, uint16_t *packet_len) {
    // Read packet length
    uint8_t len_bytes[2];
    if (fread(len_bytes, 1, 2, file) != 2) {
        if (feof(file)) {
            return 0;  // End of file
        }
        return -1;  // Read error
    }
    
    // Little endian length
    *packet_len = len_bytes[0] | (len_bytes[1] << 8);
    
    if (*packet_len == 0 || *packet_len > VFM_MAX_PACKET) {
        fprintf(stderr, "Error: Invalid packet length: %u\n", *packet_len);
        return -1;
    }
    
    // Read packet data
    if (fread(buffer, 1, *packet_len, file) != *packet_len) {
        fprintf(stderr, "Error: Failed to read packet data\n");
        return -1;
    }
    
    return 1;  // Success
}

// Create a simple test packet file if none exists
static int create_test_packets(const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        fprintf(stderr, "Error: Cannot create test packet file '%s': %s\n", filename, strerror(errno));
        return -1;
    }
    
    printf("Creating sample test packets...\n");
    
    // Create a few test packets
    uint8_t packet[128];
    uint16_t len;
    
    // Packet 1: TCP SYN packet (should be accepted by TCP filter)
    memset(packet, 0, sizeof(packet));
    len = 74;
    
    // Ethernet header
    packet[12] = 0x08; packet[13] = 0x00;  // IPv4
    
    // IP header
    packet[14] = 0x45;  // Version 4, IHL 5
    packet[23] = 0x06;  // Protocol TCP
    // Source IP: 192.168.1.100
    packet[26] = 192; packet[27] = 168; packet[28] = 1; packet[29] = 100;
    // Dest IP: 10.0.0.1
    packet[30] = 10; packet[31] = 0; packet[32] = 0; packet[33] = 1;
    
    // TCP header
    packet[34] = 0x04; packet[35] = 0xD2;  // Source port 1234
    packet[36] = 0x00; packet[37] = 0x50;  // Dest port 80
    packet[47] = 0x02;  // Flags (SYN)
    
    fwrite(&len, 2, 1, file);
    fwrite(packet, 1, len, file);
    
    // Packet 2: UDP packet (should be dropped by TCP filter)
    packet[23] = 0x11;  // Protocol UDP
    packet[47] = 0x00;  // No TCP flags
    
    fwrite(&len, 2, 1, file);
    fwrite(packet, 1, len, file);
    
    // Packet 3: Another TCP SYN packet
    packet[23] = 0x06;  // Protocol TCP
    packet[47] = 0x02;  // Flags (SYN)
    // Different source IP
    packet[26] = 192; packet[27] = 168; packet[28] = 1; packet[29] = 101;
    
    fwrite(&len, 2, 1, file);
    fwrite(packet, 1, len, file);
    
    // Packet 4: TCP ACK packet (should be dropped by SYN filter)
    packet[47] = 0x10;  // Flags (ACK)
    
    fwrite(&len, 2, 1, file);
    fwrite(packet, 1, len, file);
    
    // Packet 5: ICMP packet (should be dropped)
    packet[23] = 0x01;  // Protocol ICMP
    packet[47] = 0x00;  // No TCP flags
    
    fwrite(&len, 2, 1, file);
    fwrite(packet, 1, len, file);
    
    fclose(file);
    printf("Created 5 test packets in %s\n", filename);
    return 0;
}

// Test filter against packets
static int test_filter(const char *filter_file, const char *packet_file, int verbose) {
    // Load filter
    uint8_t *program = NULL;
    uint32_t program_size = 0;
    
    if (load_filter(filter_file, &program, &program_size) != 0) {
        return -1;
    }
    
    printf("Loaded filter: %u bytes\n", program_size);
    
    // Create VM
    vfm_state_t *vm = vfm_create();
    if (!vm) {
        fprintf(stderr, "Error: Failed to create VM\n");
        free(program);
        return -1;
    }
    
    // Load program into VM
    int result = vfm_load_program(vm, program, program_size);
    if (result != VFM_SUCCESS) {
        fprintf(stderr, "Error: Failed to load program into VM: %d\n", result);
        free(program);
        vfm_destroy(vm);
        return -1;
    }
    
    printf("Program loaded and verified successfully\n");
    
    // Open packet file
    FILE *packet_file_handle = fopen(packet_file, "rb");
    if (!packet_file_handle) {
        // Try to create test packets if file doesn't exist
        if (errno == ENOENT) {
            printf("Packet file not found, creating test packets...\n");
            if (create_test_packets(packet_file) == 0) {
                packet_file_handle = fopen(packet_file, "rb");
            }
        }
        
        if (!packet_file_handle) {
            fprintf(stderr, "Error: Cannot open packet file '%s': %s\n", packet_file, strerror(errno));
            free(program);
            vfm_destroy(vm);
            return -1;
        }
    }
    
    printf("Testing filter against packets...\n");
    
    // Test statistics
    test_stats_t stats = {0};
    stats.min_time_ns = 1e9;  // Initialize to 1 second
    
    uint8_t packet_buffer[VFM_MAX_PACKET];
    uint16_t packet_len;
    int packet_result;
    
    while ((packet_result = read_packet(packet_file_handle, packet_buffer, &packet_len)) > 0) {
        stats.total_packets++;
        
        // Time the filter execution
        double start_time = get_time_ns();
        
        result = vfm_execute(vm, packet_buffer, packet_len);
        
        double end_time = get_time_ns();
        double elapsed = end_time - start_time;
        
        // Update timing statistics
        stats.total_time_ns += elapsed;
        if (elapsed < stats.min_time_ns) stats.min_time_ns = elapsed;
        if (elapsed > stats.max_time_ns) stats.max_time_ns = elapsed;
        
        // Categorize result
        if (result == 1) {
            stats.accepted_packets++;
            if (verbose) {
                printf("Packet %llu: ACCEPT (%.1f ns)\n", stats.total_packets, elapsed);
            }
        } else if (result == 0) {
            stats.dropped_packets++;
            if (verbose) {
                printf("Packet %llu: DROP (%.1f ns)\n", stats.total_packets, elapsed);
            }
        } else {
            stats.error_packets++;
            if (verbose) {
                printf("Packet %llu: ERROR %d (%.1f ns)\n", stats.total_packets, result, elapsed);
            }
        }
    }
    
    fclose(packet_file_handle);
    free(program);
    vfm_destroy(vm);
    
    if (packet_result < 0) {
        fprintf(stderr, "Error reading packets\n");
        return -1;
    }
    
    // Print summary statistics
    printf("\n=== Test Results ===\n");
    printf("Total packets:    %llu\n", stats.total_packets);
    printf("Accepted:         %llu (%.1f%%)\n", stats.accepted_packets, 
           stats.total_packets > 0 ? 100.0 * stats.accepted_packets / stats.total_packets : 0.0);
    printf("Dropped:          %llu (%.1f%%)\n", stats.dropped_packets,
           stats.total_packets > 0 ? 100.0 * stats.dropped_packets / stats.total_packets : 0.0);
    printf("Errors:           %llu (%.1f%%)\n", stats.error_packets,
           stats.total_packets > 0 ? 100.0 * stats.error_packets / stats.total_packets : 0.0);
    
    if (stats.total_packets > 0) {
        double avg_time = stats.total_time_ns / stats.total_packets;
        double mpps = 1e9 / avg_time;  // Million packets per second
        
        printf("\n=== Performance ===\n");
        printf("Average time:     %.1f ns/packet\n", avg_time);
        printf("Min time:         %.1f ns/packet\n", stats.min_time_ns);
        printf("Max time:         %.1f ns/packet\n", stats.max_time_ns);
        printf("Throughput:       %.2f Mpps\n", mpps);
        printf("Total time:       %.2f ms\n", stats.total_time_ns / 1e6);
    }
    
    return 0;
}

int main(int argc, char *argv[]) {
    int verbose = 0;
    
    if (argc < 3) {
        printf("VFM Filter Test Tool\n");
        printf("Usage: %s <filter.bin> <packets.pkt> [-v]\n", argv[0]);
        printf("\n");
        printf("Options:\n");
        printf("  -v    Verbose output (show per-packet results)\n");
        printf("\n");
        printf("Packet file format:\n");
        printf("  Simple binary format with 2-byte length + packet data\n");
        printf("  If packet file doesn't exist, sample packets will be created\n");
        return 1;
    }
    
    const char *filter_file = argv[1];
    const char *packet_file = argv[2];
    
    // Check for verbose flag
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        }
    }
    
    printf("VFM Filter Test Tool\n");
    printf("Filter: %s\n", filter_file);
    printf("Packets: %s\n", packet_file);
    if (verbose) printf("Verbose mode enabled\n");
    printf("\n");
    
    return test_filter(filter_file, packet_file, verbose);
}