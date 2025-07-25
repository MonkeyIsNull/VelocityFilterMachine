#include "vfm.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h>
#ifdef __APPLE__
#include <pthread.h>
#endif

#ifdef __aarch64__

// ARM64 JIT implementation
typedef struct vfm_jit_arm64 {
    uint8_t *code;
    size_t code_size;
    size_t code_pos;
} vfm_jit_arm64_t;

// ARM64 instruction encoding helpers
static void emit_u32(vfm_jit_arm64_t *jit, uint32_t insn) {
    if (jit->code_pos + 4 <= jit->code_size) {
        *(uint32_t*)(jit->code + jit->code_pos) = insn;
        jit->code_pos += 4;
    }
}

// ARM64 register encoding
#define ARM64_X0  0
#define ARM64_X1  1
#define ARM64_X2  2
#define ARM64_X3  3
#define ARM64_X19 19
#define ARM64_X20 20
#define ARM64_X21 21
#define ARM64_X29 29  // FP
#define ARM64_X30 30  // LR
#define ARM64_SP  31

// Emit MOV immediate
static void emit_mov_imm(vfm_jit_arm64_t *jit, int rd, uint64_t imm) {
    // MOV Xd, #imm (simplified - only handles 16-bit immediates)
    uint32_t insn = 0xd2800000 | (imm << 5) | rd;
    emit_u32(jit, insn);
}

// Emit ADD register
static void emit_add_reg(vfm_jit_arm64_t *jit, int rd, int rn, int rm) {
    // ADD Xd, Xn, Xm
    uint32_t insn = 0x8b000000 | (rm << 16) | (rn << 5) | rd;
    emit_u32(jit, insn);
}

// Emit LDR immediate
static void emit_ldr_imm(vfm_jit_arm64_t *jit, int rt, int rn, int imm) {
    // LDR Xt, [Xn, #imm]
    uint32_t insn = 0xf9400000 | ((imm >> 3) << 10) | (rn << 5) | rt;
    emit_u32(jit, insn);
}

// Emit STR immediate
static void emit_str_imm(vfm_jit_arm64_t *jit, int rt, int rn, int imm) {
    // STR Xt, [Xn, #imm]
    uint32_t insn = 0xf9000000 | ((imm >> 3) << 10) | (rn << 5) | rt;
    emit_u32(jit, insn);
}

// Emit RET
static void emit_ret(vfm_jit_arm64_t *jit) {
    // RET X30
    emit_u32(jit, 0xd65f03c0);
}

// Emit function prologue
static void emit_prologue(vfm_jit_arm64_t *jit) {
    // stp x29, x30, [sp, #-16]!
    emit_u32(jit, 0xa9bf7bfd);
    // mov x29, sp
    emit_u32(jit, 0x910003fd);
    // stp x19, x20, [sp, #-16]!
    emit_u32(jit, 0xa9bf53f3);
    // stp x21, x22, [sp, #-16]!
    emit_u32(jit, 0xa9bf5bf5);
}

// Emit function epilogue
static void emit_epilogue(vfm_jit_arm64_t *jit) {
    // ldp x21, x22, [sp], #16
    emit_u32(jit, 0xa8c15bf5);
    // ldp x19, x20, [sp], #16
    emit_u32(jit, 0xa8c153f3);
    // ldp x29, x30, [sp], #16
    emit_u32(jit, 0xa8c17bfd);
    emit_ret(jit);
}

// Helper function to flush cache and protect memory for execution
static bool flush_and_protect_memory(uint8_t *code, size_t code_pos, size_t code_size) {
#ifdef __APPLE__
    // Flush instruction cache and switch to execute mode
    sys_icache_invalidate(code, code_pos);
    pthread_jit_write_protect_np(1);
    
    if (mprotect(code, code_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(code, code_size);
        return false;
    }
#else
    // On other ARM64 systems, just flush the instruction cache
    __builtin___clear_cache((char*)code, (char*)code + code_pos);
#endif
    return true;
}

// JIT compile for ARM64
void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len) {
    size_t code_size = 4096;
    
#ifdef __APPLE__
    // On Apple Silicon, use MAP_JIT for JIT compilation
    uint8_t *code = mmap(NULL, code_size, PROT_READ | PROT_WRITE, 
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
    // On other ARM64 systems, use traditional RWX mapping
    uint8_t *code = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    
    if (code == MAP_FAILED) {
        return NULL;
    }
    
    vfm_jit_arm64_t jit = {
        .code = code,
        .code_size = code_size,
        .code_pos = 0
    };
    
#ifdef __APPLE__
    // On Apple Silicon, disable write protection before generating JIT code
    // This is REQUIRED - without this call, hardened runtime may prevent
    // writing instructions to the allocated MAP_JIT pages
    pthread_jit_write_protect_np(0);
#endif
    
    emit_prologue(&jit);
    
    // Register allocation:
    // X0 = VM state pointer
    // X1 = Packet pointer
    // X2 = Packet length
    // X19 = Stack pointer (VM)
    // X20 = Program counter
    // X21 = Stack base pointer
    
    // Initialize VM registers
    emit_ldr_imm(&jit, ARM64_X21, ARM64_X0, 8);  // Load stack pointer
    emit_mov_imm(&jit, ARM64_X19, 0);            // Initialize SP
    emit_mov_imm(&jit, ARM64_X20, 0);            // Initialize PC
    
    // Compile instructions
    for (uint32_t pc = 0; pc < len; ) {
        uint8_t opcode = program[pc++];
        
        switch (opcode) {
            case VFM_PUSH: {
                uint64_t imm = *(uint64_t*)&program[pc];
                pc += 8;
                
                // Load immediate into X3
                emit_mov_imm(&jit, ARM64_X3, imm & 0xFFFF);
                
                // Store to stack: stack[++sp] = imm
                emit_add_reg(&jit, ARM64_X19, ARM64_X19, ARM64_X1);  // sp++
                emit_str_imm(&jit, ARM64_X3, ARM64_X21, 0);          // stack[sp] = imm
                break;
            }
            
            case VFM_ADD: {
                // Pop two values and add them
                emit_ldr_imm(&jit, ARM64_X2, ARM64_X21, 0);          // b = stack[sp]
                emit_ldr_imm(&jit, ARM64_X3, ARM64_X21, -8);         // a = stack[sp-1]
                emit_add_reg(&jit, ARM64_X3, ARM64_X3, ARM64_X2);    // a + b
                emit_str_imm(&jit, ARM64_X3, ARM64_X21, -8);         // stack[sp-1] = result
                // sp-- (decrement stack pointer)
                break;
            }
            
            case VFM_RET: {
                // Return top of stack
                emit_ldr_imm(&jit, ARM64_X0, ARM64_X21, 0);  // Load return value
                emit_epilogue(&jit);
                
                if (!flush_and_protect_memory(jit.code, jit.code_pos, jit.code_size)) {
                    return NULL;
                }
                
                return jit.code;
            }
            
            default:
                // Unsupported instruction - fall back to interpreter
                emit_mov_imm(&jit, ARM64_X0, -1);  // Return error
                emit_epilogue(&jit);
                
                if (!flush_and_protect_memory(jit.code, jit.code_pos, jit.code_size)) {
                    return NULL;
                }
                
                return jit.code;
        }
    }
    
    // Default return
    emit_mov_imm(&jit, ARM64_X0, 0);
    emit_epilogue(&jit);
    
    if (!flush_and_protect_memory(jit.code, jit.code_pos, jit.code_size)) {
        return NULL;
    }
    
    return jit.code;
}

// Check if JIT is available
bool vfm_jit_available_arm64(void) {
#ifdef __APPLE__
    // On Apple Silicon, JIT requires the hardened runtime entitlement
    // Try to allocate JIT memory to check if it's available
    void *test_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, 
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    if (test_mem == MAP_FAILED) {
        return false;  // JIT not available (missing entitlement)
    }
    munmap(test_mem, 4096);
    return true;
#else
    return true;  // ARM64 JIT is available on non-Apple systems
#endif
}

#else

// Stub for non-ARM64 platforms
void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len) {
    (void)program;
    (void)len;
    return NULL;
}

bool vfm_jit_available_arm64(void) {
    return false;
}

#endif