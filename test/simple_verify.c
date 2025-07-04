#include "src/vfm.h"
#include <stdio.h>

int main() {
    uint8_t program[] = {
        4, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // PUSH 1
        22  // RET
    };
    
    printf("About to verify simple program\n");
    int result = vfm_verify(program, sizeof(program));
    printf("Verification result: %d\n", result);
    return 0;
}
