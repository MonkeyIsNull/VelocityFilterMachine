#include <stdio.h>
#include <stdlib.h>
#include "../src/vfm.h"

int main(int argc, char *argv[]) {
    printf("VFM Disassembler (stub implementation)\n");
    
    if (argc < 2) {
        printf("Usage: %s <input.bin>\n", argv[0]);
        return 1;
    }
    
    printf("Would disassemble: %s\n", argv[1]);
    printf("Disassembler not yet implemented.\n");
    
    return 0;
}