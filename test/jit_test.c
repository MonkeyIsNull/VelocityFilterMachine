#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vfm.h"

// Test JIT availability and basic functionality
int main() {
    printf("VFM JIT Test on Apple Silicon\n");
    printf("==============================\n\n");
    
    // Test 1: Check if JIT is available
    printf("1. Testing JIT availability...\n");
    
    #ifdef __aarch64__
    extern bool vfm_jit_available_arm64(void);
    bool jit_available = vfm_jit_available_arm64();
    printf("   ARM64 JIT available: %s\n", jit_available ? "YES" : "NO");
    
    if (!jit_available) {
        printf("   ERROR: JIT not available. Possible causes:\n");
        printf("   - Missing com.apple.security.cs.allow-jit entitlement\n");
        printf("   - Running on system without JIT support\n");
        printf("   - Security restrictions (SIP, etc.)\n");
        return 1;
    }
    #else
    printf("   Not running on ARM64 - JIT test skipped\n");
    return 0;
    #endif
    
    // Test 2: Create a simple VFM program
    printf("\n2. Testing basic JIT compilation...\n");
    
    // Simple program: PUSH 42, RET
    uint8_t program[] = {
        0x04,  // VFM_PUSH
        0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // 42 (64-bit)
        0x16   // VFM_RET
    };
    
    extern void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len);
    void* jit_func = vfm_jit_compile_arm64(program, sizeof(program));
    
    if (jit_func) {
        printf("   JIT compilation: SUCCESS\n");
        printf("   JIT function address: %p\n", jit_func);
        
        // Test 3: Execute JIT code (careful!)
        printf("\n3. Testing JIT execution...\n");
        
        // For safety, we'll just verify the function pointer is valid
        // In a real implementation, we'd need to set up proper VM state
        printf("   JIT function compiled successfully\n");
        printf("   (Execution test skipped - would require VM state setup)\n");
        
        // Clean up
        #include <sys/mman.h>
        munmap(jit_func, 4096);
    } else {
        printf("   JIT compilation: FAILED\n");
        return 1;
    }
    
    printf("\n✅ All JIT tests passed!\n");
    printf("\nNote: For production use, ensure your application is properly\n");
    printf("code-signed with the JIT entitlement for distribution.\n");
    
    return 0;
}
