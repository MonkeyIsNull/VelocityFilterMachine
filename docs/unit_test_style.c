#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "../src/vfm.h"

// Same as unit tests
static uint8_t* create_test_packet(uint16_t *len) {
    static uint8_t packet[128];
    *len = 128;
    
    // Ethernet header
    for (int i = 0; i < 14; i++) packet[i] = 0;
    packet[12] = 0x08; packet[13] = 0x00;  // IPv4
    
    // IP header
    packet[14] = 0x45;  // Version 4, IHL 5
    packet[15] = 0x00;  // TOS
    packet[16] = 0x00; packet[17] = 0x54;  // Total length
    packet[18] = 0x00; packet[19] = 0x00;  // ID
    packet[20] = 0x40; packet[21] = 0x00;  // Flags & Fragment offset
    packet[22] = 0x40;  // TTL
    packet[23] = 0x06;  // Protocol (TCP)
    packet[24] = 0x00; packet[25] = 0x00;  // Checksum
    // Source IP: 192.168.1.100
    packet[26] = 192; packet[27] = 168; packet[28] = 1; packet[29] = 100;
    // Dest IP: 10.0.0.1
    packet[30] = 10; packet[31] = 0; packet[32] = 0; packet[33] = 1;
    
    // TCP header
    packet[34] = 0x04; packet[35] = 0xD2;  // Source port 1234
    packet[36] = 0x00; packet[37] = 0x50;  // Dest port 80
    packet[38] = 0x00; packet[39] = 0x00; packet[40] = 0x00; packet[41] = 0x01;  // Seq
    packet[42] = 0x00; packet[43] = 0x00; packet[44] = 0x00; packet[45] = 0x00;  // Ack
    packet[46] = 0x50;  // Data offset
    packet[47] = 0x02;  // Flags (SYN)
    packet[48] = 0x20; packet[49] = 0x00;  // Window
    packet[50] = 0x00; packet[51] = 0x00;  // Checksum
    packet[52] = 0x00; packet[53] = 0x00;  // Urgent
    
    return packet;
}

int main() {
    vfm_state_t *vm = vfm_create();
    if (!vm) {
        fprintf(stderr, "Failed to create VM\n");
        return 1;
    }
    
    // Exact same as unit test
    uint8_t program[] = {
        4, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push 0x42
        22  // Return
    };
    
    printf("Loading program: %zu bytes\n", sizeof(program));
    
    int result = vfm_load_program(vm, program, sizeof(program));
    if (result != VFM_SUCCESS) {
        fprintf(stderr, "Failed to load program: %d\n", result);
        vfm_destroy(vm);
        return 1;
    }
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    printf("Executing with packet length %u\n", packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    
    if (result == 0x42) {
        printf("SUCCESS: Result = %d (0x%x)\n", result, result);
    } else {
        printf("FAILURE: Result = %d (expected 0x42 = 66)\n", result);
    }
    
    vfm_destroy(vm);
    return 0;
}