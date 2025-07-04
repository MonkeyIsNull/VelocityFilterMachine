#include "src/vfm.h"
#include "src/opcodes.h"
#include <stdio.h>

int main() {
    uint8_t program[] = {
        VFM_LD16, 12, 0x00,  // Load EtherType
        VFM_PUSH, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push 0x0800 (IPv4)
        VFM_JEQ, 0x0A, 0x00,  // Jump if IPv4 (10 bytes forward)
        VFM_PUSH, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Push 0 (drop)
        VFM_RET,
        VFM_PUSH, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Push 1 (accept)
        VFM_RET
    };
    
    printf("Program size: %zu bytes\n", sizeof(program));
    for (int i = 0; i < sizeof(program); i++) {
        printf("%d: 0x%02x\n", i, program[i]);
    }
    
    int result = vfm_verify(program, sizeof(program));
    printf("Verification result: %d (%s)\n", result, vfm_error_string(result));
    
    return 0;
}
