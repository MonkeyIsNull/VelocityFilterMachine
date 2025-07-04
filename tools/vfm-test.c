#include <stdio.h>
#include <stdlib.h>
#include "../src/vfm.h"

int main(int argc, char *argv[]) {
    printf("VFM Test Tool (stub implementation)\n");
    
    if (argc < 3) {
        printf("Usage: %s <filter.bin> <packets.pcap>\n", argv[0]);
        return 1;
    }
    
    printf("Would test filter: %s\n", argv[1]);
    printf("Against packets: %s\n", argv[2]);
    printf("Test tool not yet implemented.\n");
    
    return 0;
}