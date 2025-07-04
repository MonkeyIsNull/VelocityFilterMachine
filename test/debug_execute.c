#include "src/vfm.h"
#include <stdio.h>

int main() {
    vfm_state_t *vm = vfm_create();
    
    uint8_t program[] = {
        4, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // PUSH 1
        22  // RET
    };
    
    printf("Loading program...\n");
    int result = vfm_load_program(vm, program, sizeof(program));
    printf("Load result: %d\n", result);
    
    uint8_t packet[128] = {0};
    packet[12] = 0x08; packet[13] = 0x00;  // IPv4
    
    printf("About to execute...\n");
    result = vfm_execute(vm, packet, 128);
    printf("Execute result: %d\n", result);
    
    vfm_destroy(vm);
    return 0;
}
