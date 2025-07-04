#include <stdio.h>
#include <stdlib.h>
#include "../src/vfm.h"

int main(int argc, char *argv[]) {
    printf("VFM Assembler (stub implementation)\n");
    
    if (argc < 2) {
        printf("Usage: %s <input.vfm> [-o output.bin]\n", argv[0]);
        return 1;
    }
    
    printf("Would assemble: %s\n", argv[1]);
    printf("Assembler not yet implemented.\n");
    
    return 0;
}