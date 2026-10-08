#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>

#include "../include/vfm.h"

// JIT compile entry points (compiled per host architecture; see Makefile).
#ifdef __aarch64__
extern void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len);
extern bool vfm_jit_available_arm64(void);
#elif defined(__x86_64__)
extern void* vfm_jit_compile_x86_64(const uint8_t *program, uint32_t len);
#endif

// Test framework macros
#define TEST_ASSERT(condition) \
    do { \
        if (!(condition)) { \
            printf("ASSERTION FAILED: %s at %s:%d\n", #condition, __FILE__, __LINE__); \
            return -1; \
        } \
    } while(0)

#define TEST_ASSERT_EQ(expected, actual) \
    do { \
        if ((expected) != (actual)) { \
            printf("ASSERTION FAILED: Expected %ld, got %ld at %s:%d\n", \
                   (long)(expected), (long)(actual), __FILE__, __LINE__); \
            return -1; \
        } \
    } while(0)

#define RUN_TEST(test_func) \
    do { \
        printf("Running " #test_func "... "); \
        fflush(stdout); \
        int result = test_func(); \
        if (result == 0) { \
            printf("PASSED\n"); \
            tests_passed++; \
        } else { \
            printf("FAILED\n"); \
            tests_failed++; \
        } \
        total_tests++; \
    } while(0)

// Global test counters
static int total_tests = 0;
static int tests_passed = 0;
static int tests_failed = 0;

// Helper function to create a simple test packet
static uint8_t* create_test_packet(uint16_t *len) {
    static uint8_t packet[128];
    *len = 128;
    
    // Ethernet header
    memset(packet, 0, 14);
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

// Test VM creation and destruction
static int test_vm_creation(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    TEST_ASSERT(vm->hot.stack != NULL);
    TEST_ASSERT(vm->hot.stack_size == VFM_MAX_STACK);
    TEST_ASSERT(vm->hot.insn_limit == VFM_MAX_INSN);
    
    vfm_destroy(vm);
    return 0;
}

// Test bounds checking
static int test_bounds_checking(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Create a program that tries to read beyond packet bounds
    uint8_t program[] = {
        VFM_LD32, 126, 0,  // Try to read 4 bytes at offset 126 (126+4=130 > 128)
        VFM_RET
    };
    
    int result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    // This should fail with bounds error  
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(VFM_ERROR_BOUNDS, result);
    
    vfm_destroy(vm);
    return 0;
}

// Test stack operations
static int test_stack_operations(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Test PUSH and POP
    uint8_t program[] = {
        VFM_PUSH, 0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push 0x42
        VFM_RET  // Return with 0x42
    };
    
    int result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(0x42, result);
    
    vfm_destroy(vm);
    return 0;
}

// Test arithmetic operations
static int test_arithmetic(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Test 10 + 5 = 15
    uint8_t program[] = {
        VFM_PUSH, 10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push 10
        VFM_PUSH, 5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Push 5
        VFM_ADD,     // Add them
        VFM_RET      // Return result
    };
    
    int result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(15, result);
    
    vfm_destroy(vm);
    return 0;
}

// Test packet loading
static int test_packet_loading(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Load the EtherType field (should be 0x0800 for IPv4)
    uint8_t program[] = {
        VFM_LD16, 12, 0x00,  // Load 16 bits at offset 12 (EtherType)
        VFM_RET
    };
    
    int result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(0x0800, result);
    
    vfm_destroy(vm);
    return 0;
}

// Test conditional jumps
static int test_conditional_jumps(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Test JEQ - jump if equal
    uint8_t program[] = {
        VFM_PUSH, 10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push 10
        VFM_PUSH, 10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push 10
        VFM_JEQ, 0x0A, 0x00,  // Jump 10 bytes if equal
        VFM_PUSH, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Push 0 (shouldn't execute)
        VFM_RET,              // Return 0
        VFM_PUSH, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Push 1 (jump target)
        VFM_RET               // Return 1
    };
    
    int result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(1, result);  // Should jump and return 1
    
    vfm_destroy(vm);
    return 0;
}

// Test program verification
static int test_verification(void) {
    // Test valid program
    uint8_t valid_program[] = {
        VFM_PUSH, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        VFM_RET
    };
    
    int result = vfm_verify(valid_program, sizeof(valid_program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    // Test invalid program (jump out of bounds)
    uint8_t invalid_program[] = {
        VFM_JMP, 0xFF, 0x7F,  // Jump way beyond program end
        VFM_RET
    };
    
    result = vfm_verify(invalid_program, sizeof(invalid_program));
    TEST_ASSERT_EQ(VFM_ERROR_VERIFICATION_FAILED, result);
    
    return 0;
}

// Test flow table operations
static int test_flow_table(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Initialize flow table
    int result = vfm_flow_table_init(vm, 1024);
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    // Test flow operations: store key=100, value=200, then load key=100
    uint8_t program[] = {
        VFM_PUSH, 100, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push key 100
        VFM_PUSH, 200, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push value 200
        VFM_FLOW_STORE,  // Store key=100, value=200
        VFM_PUSH, 100, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push key 100
        VFM_FLOW_LOAD,   // Load value for key 100
        VFM_RET          // Return the loaded value
    };
    
    result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(200, result);  // Should return stored value
    
    vfm_destroy(vm);
    return 0;
}

// Test hash function
static int test_hash_function(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Test HASH5 instruction
    uint8_t program[] = {
        VFM_HASH5,  // Hash 5-tuple
        VFM_RET     // Return hash value
    };
    
    int result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT(result != 0);  // Hash should not be zero
    
    vfm_destroy(vm);
    return 0;
}

// Test stack overflow protection
static int test_stack_overflow(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Create a smaller program that tests stack overflow
    // Just enough to exceed the limit (30 pushes should be safe)
    uint8_t program[512];
    int pos = 0;
    
    // Push 30 values (well within program size limits)
    for (int i = 0; i < 30; i++) {
        program[pos++] = VFM_PUSH;
        for (int j = 0; j < 8; j++) {
            program[pos++] = i;
        }
    }
    program[pos++] = VFM_RET;
    
    int result = vfm_load_program(vm, program, pos);
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    // Reduce stack limit to trigger overflow
    vm->hot.stack_size = 20;  // Force overflow at 20 instead of 256
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(VFM_ERROR_STACK_OVERFLOW, result);
    
    vfm_destroy(vm);
    return 0;
}

// Test instruction limit enforcement
static int test_instruction_limit(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Set a very low instruction limit
    vm->hot.insn_limit = 10;
    
    // Create a program with many instructions
    uint8_t program[1024];
    int pos = 0;
    
    // Add many PUSH instructions
    for (int i = 0; i < 20; i++) {
        program[pos++] = VFM_PUSH;
        for (int j = 0; j < 8; j++) {
            program[pos++] = i;
        }
    }
    program[pos++] = VFM_RET;
    
    int result = vfm_load_program(vm, program, pos);
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(VFM_ERROR_LIMIT, result);
    
    vfm_destroy(vm);
    return 0;
}

// Test division by zero detection
static int test_division_by_zero(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Test division by zero
    uint8_t program[] = {
        VFM_PUSH, 10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // Push 10
        VFM_PUSH, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Push 0
        VFM_DIV,     // Divide by zero
        VFM_RET      // Return result
    };
    
    int result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(VFM_ERROR_DIVISION_BY_ZERO, result);
    
    vfm_destroy(vm);
    return 0;
}

// Basic sanity/performance smoke test
static int test_performance(void) {
    // Simple performance test - just verify basic VM functionality
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // Very simple accept-all program
    uint8_t program[] = {
        VFM_PUSH, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Push 1
        VFM_RET  // Return
    };
    
    int result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    // Just run once to verify it works
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(1, result);
    
    printf("\nBasic VM performance test passed\n");
    
    vfm_destroy(vm);
    return 0;
}

// Real-world filter test (TCP SYN detection)
static int test_tcp_syn_filter(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);
    
    // TCP SYN detection filter
    uint8_t program[] = {
        VFM_LD16, 12, 0x00,  // Load EtherType
        VFM_PUSH, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // IPv4
        VFM_JNE, 0x28, 0x00,  // Jump to reject if not IPv4 (40 bytes)
        
        VFM_LD8, 23, 0x00,   // Load IP protocol
        VFM_PUSH, 6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    // TCP
        VFM_JNE, 0x19, 0x00,  // Jump to reject if not TCP (25 bytes)
        
        VFM_LD8, 47, 0x00,   // Load TCP flags
        VFM_PUSH, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SYN flag
        VFM_AND,             // Check if SYN is set
        VFM_PUSH, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SYN flag
        VFM_JEQ, 0x0A, 0x00,  // Jump to accept if SYN (10 bytes)
        
        // reject:
        VFM_PUSH, 0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Push 0 (drop)
        VFM_RET,
        // accept:
        VFM_PUSH, 1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // Push 1 (accept)
        VFM_RET
    };
    
    int result = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, result);
    
    uint16_t packet_len;
    uint8_t *packet = create_test_packet(&packet_len);
    
    result = vfm_execute(vm, packet, packet_len);
    TEST_ASSERT_EQ(1, result);  // Should accept TCP SYN packets
    
    vfm_destroy(vm);
    return 0;
}

// Regression: the JIT must DECLINE (return NULL -> interpreter) for any
// opcode it cannot correctly compile, instead of emitting a stub that
// fabricates a wrong answer. This is a direct, entitlement-independent
// discriminator: it calls the compile function directly and inspects the
// returned pointer, so it is deterministic even on an unsigned test binary
// where vfm_jit_available_arm64() is false and execution would otherwise
// run the interpreter either way.
//
// Pre-fix behavior (the bug): the compile function returned a NON-NULL stub
//   - arm64 default case emitted a truncated MOVZ of -1 (garbage return)
//   - x86-64 default case emitted `mov RAX, 0` (silent DROP)
// Post-fix: the compile function returns NULL and vfm_load_program falls
// back to the correct bounds-checked interpreter.
static int test_jit_declines_unsupported_opcode(void) {
#ifdef __aarch64__
    // A gate-passing program whose FIRST opcode (LD8 @ IPv4 proto offset 23)
    // is NOT implemented by the arm64 JIT -> must bail to NULL.
    // (= proto 6)-shaped: LD8@23, PUSH 6, JEQ accept, PUSH 0, RET, PUSH 1, RET
    uint8_t unsupported[] = {
        VFM_LD8, 23, 0x00,                                      // load proto byte
        VFM_PUSH, 6, 0,0,0,0,0,0,0,                             // push 6 (TCP)
        VFM_JEQ, 0x0A, 0x00,                                    // if equal -> accept (+10)
        VFM_PUSH, 0, 0,0,0,0,0,0,0,                             // reject
        VFM_RET,
        VFM_PUSH, 1, 0,0,0,0,0,0,0,                             // accept
        VFM_RET
    };
    // Pre-fix returned a non-NULL stub; post-fix returns NULL. This holds
    // whether or not the JIT entitlement is present (if absent, the MAP_JIT
    // mmap fails and the function also returns NULL).
    void *bad = vfm_jit_compile_arm64(unsupported, sizeof(unsupported));
    TEST_ASSERT(bad == NULL);

    // An all-implemented program (PUSH, ADD, RET) must still compile to a
    // real function pointer -- proving the working fast path is untouched.
    // Guard on availability: without the entitlement the MAP_JIT mmap fails.
    if (vfm_jit_available_arm64()) {
        uint8_t supported[] = {
            VFM_PUSH, 2, 0,0,0,0,0,0,0,                         // push 2
            VFM_PUSH, 3, 0,0,0,0,0,0,0,                         // push 3
            VFM_ADD,                                            // add
            VFM_RET
        };
        void *good = vfm_jit_compile_arm64(supported, sizeof(supported));
        TEST_ASSERT(good != NULL);
        munmap(good, 4096);  // arm64 JIT uses a fixed 4096-byte page
    }
#elif defined(__x86_64__)
    // Control flow is NOT compiled by the x86-64 single-core JIT: the old branch
    // emitters used a bogus `vfm_offset * 16` displacement (and signed jumps for
    // the interpreter's unsigned compares), so every branch targeted an
    // arbitrary address. A correct VFM-pc -> x86-offset fixup pass is not
    // implemented, so any branch (JGE here, and likewise JEQ/JNE/JGT/JLT/JMP)
    // DECLINES to the interpreter -- exactly the #10/#11 "never emit code we
    // cannot prove against the oracle" discipline. This mirrors the ARM64 half
    // of this test, where a branch program is the unsupported example.
    uint8_t unsupported[] = {
        VFM_LD16, 36, 0x00,                                    // load dst port
        VFM_PUSH, 0, 0,0,0,0,0,0,0,                            // push 0
        VFM_JGE, 0x0A, 0x00,                                   // >= -> accept (+10)
        VFM_PUSH, 0, 0,0,0,0,0,0,0,                            // reject
        VFM_RET,
        VFM_PUSH, 1, 0,0,0,0,0,0,0,                            // accept
        VFM_RET
    };
    void *bad = vfm_jit_compile_x86_64(unsupported, sizeof(unsupported));
    TEST_ASSERT(bad == NULL);

    // A program built only from oracle-validated x86 emitters (LD16, PUSH,
    // ADD, RET) must still compile to a real function pointer -- proving the
    // working fast path is untouched.
    uint8_t supported[] = {
        VFM_LD16, 36, 0x00,                                    // load dst port
        VFM_PUSH, 80, 0,0,0,0,0,0,0,                           // push 80
        VFM_ADD,                                               // add
        VFM_RET
    };
    void *good = vfm_jit_compile_x86_64(supported, sizeof(supported));
    TEST_ASSERT(good != NULL);
    munmap(good, sizeof(supported) * 32);  // x86-64 JIT uses len*32 bytes
#else
    printf("(no JIT backend for this arch - skipped) ");
#endif
    return 0;
}

// Regression (headline): a dst-port filter that SHOULD match must return a
// nonzero (accept) result under the DEFAULT build. On Apple Silicon this
// filter uses LD16 (load the 16-bit L4 port), an opcode the arm64 JIT does
// not implement. Pre-fix, the arm64 JIT emitted a drop/garbage stub and this
// filter matched ZERO packets silently. Post-fix, the JIT declines
// (vm->cold.jit_code stays NULL) and the correct interpreter runs it.
static int test_port_filter_matches_under_default_build(void) {
    vfm_state_t *vm = vfm_create();
    TEST_ASSERT(vm != NULL);

    // (= dst-port 443): LD16@36, PUSH 443, JEQ accept(+10), PUSH 0, RET,
    //                   PUSH 1, RET. Unique bytecode to avoid the global
    //                   JIT cache returning a stale cross-test entry.
    uint8_t program[] = {
        VFM_LD16, 36, 0x00,                                    // load dst port (offset 36)
        VFM_PUSH, 0xBB, 0x01, 0,0,0,0,0,0,                     // push 443 (0x01BB)
        VFM_JEQ, 0x0A, 0x00,                                   // if equal -> accept (+10)
        VFM_PUSH, 0, 0,0,0,0,0,0,0,                            // reject (drop)
        VFM_RET,
        VFM_PUSH, 1, 0,0,0,0,0,0,0,                            // accept
        VFM_RET
    };

#ifdef __aarch64__
    // Initialize the shared JIT cache so a successful JIT compile is actually
    // INSTALLED into the VM. vfm_jit_cache_store() returns NULL when the cache
    // is uninitialized, which would otherwise discard any compiled code and
    // silently run the interpreter regardless -- masking the bug. The
    // embedding application (PacketVelocity) initializes this cache, so this
    // mirrors the real deployment in which the Apple Silicon silent-wrong-
    // answer manifested. We destroy it again at the end of this test so the
    // process-global cache does not leak into the other tests.
    //
    // Pre-fix on arm64: LD16 (load the 16-bit L4 port) is not implemented by
    // the JIT, so the old default case emitted a garbage stub that WAS
    // installed and executed -- returning a wrong answer / SIGILL, matching
    // ZERO packets silently. Post-fix: the JIT declines (returns NULL),
    // jit_code stays NULL, and the correct bounds-checked interpreter runs.
    vfm_jit_cache_init(NULL);
#endif

    int rc = vfm_load_program(vm, program, sizeof(program));
    TEST_ASSERT_EQ(VFM_SUCCESS, rc);

#ifdef __aarch64__
    // Post-fix the JIT must have declined this LD16-containing program.
    TEST_ASSERT(vm->cold.jit_code == NULL);
#endif

    // Packet with dst port 443 at offset 36 -> MUST match (nonzero).
    uint8_t packet[64];
    memset(packet, 0, sizeof(packet));
    packet[36] = 0x01; packet[37] = 0xBB;  // dst port 443, network order
    int result = vfm_execute(vm, packet, sizeof(packet));
    TEST_ASSERT_EQ(1, result);  // accept: nonzero match (FAILED pre-fix on arm64)

    // Packet with a different dst port (80) -> must NOT match.
    packet[36] = 0x00; packet[37] = 0x50;  // dst port 80
    result = vfm_execute(vm, packet, sizeof(packet));
    TEST_ASSERT_EQ(0, result);  // reject: no match

    vfm_destroy(vm);
#ifdef __aarch64__
    vfm_jit_cache_destroy();  // restore process-global state for other tests
#endif
    return 0;
}

// Run all tests
int main(void) {
    printf("VFM Unit Tests\n");
    printf("==============\n\n");
    
    RUN_TEST(test_vm_creation);
    RUN_TEST(test_bounds_checking);
    RUN_TEST(test_stack_operations);
    RUN_TEST(test_arithmetic);
    RUN_TEST(test_packet_loading);
    RUN_TEST(test_conditional_jumps);
    RUN_TEST(test_verification);
    RUN_TEST(test_flow_table);
    RUN_TEST(test_hash_function);
    RUN_TEST(test_stack_overflow);
    RUN_TEST(test_instruction_limit);
    RUN_TEST(test_division_by_zero);
    RUN_TEST(test_tcp_syn_filter);
    RUN_TEST(test_jit_declines_unsupported_opcode);
    RUN_TEST(test_port_filter_matches_under_default_build);
    RUN_TEST(test_performance);
    
    printf("\n==============\n");
    printf("Tests: %d total, %d passed, %d failed\n", 
           total_tests, tests_passed, tests_failed);
    
    if (tests_failed > 0) {
        printf("Some tests failed!\n");
        return 1;
    } else {
        printf("All tests passed!\n");
        return 0;
    }
}