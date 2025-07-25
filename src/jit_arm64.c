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
#define ARM64_X4  4
#define ARM64_X19 19
#define ARM64_X20 20
#define ARM64_X21 21
#define ARM64_X22 22
#define ARM64_X23 23
#define ARM64_X29 29  // FP
#define ARM64_X30 30  // LR
#define ARM64_SP  31

// ARM64 NEON Q-register encoding (128-bit vector registers)
#define ARM64_Q0  0
#define ARM64_Q1  1
#define ARM64_Q2  2
#define ARM64_Q3  3
#define ARM64_Q4  4
#define ARM64_Q5  5
#define ARM64_Q6  6
#define ARM64_Q7  7

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

// Emit SUB immediate
static void emit_sub_imm(vfm_jit_arm64_t *jit, int rd, int rn, int imm) {
    // SUB Xd, Xn, #imm
    uint32_t insn = 0xd1000000 | (imm << 10) | (rn << 5) | rd;
    emit_u32(jit, insn);
}

// Emit UMOV (extract vector element to general register)
static void emit_umov_x(vfm_jit_arm64_t *jit, int rd, int vn, int index) {
    // UMOV Xd, Vn.D[index] - extract 64-bit element to X register
    uint32_t insn = 0x4e083c00 | ((index & 1) << 20) | (vn << 5) | rd;
    emit_u32(jit, insn);
}

// Helper: calculate stack128 address from index
// Input: sp128_index in ARM64_X22, base in ARM64_X23
// Output: address in ARM64_X4
static void emit_calc_stack128_addr(vfm_jit_arm64_t *jit) {
    emit_mov_imm(jit, ARM64_X4, 16);                   // 16 bytes per vfm_u128_t
    // X4 = sp128 * 16 (multiply index by element size)
    // For ARM64, we can use shift left by 4 (since 16 = 2^4)
    emit_u32(jit, 0xd37ef484);  // LSL X4, X22, #4
    emit_add_reg(jit, ARM64_X4, ARM64_X23, ARM64_X4);  // X4 = base + (sp128 * 16)
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

// Emit NEON 128-bit load (LDR Qd, [Xn, #imm])
static void emit_ldr_q_imm(vfm_jit_arm64_t *jit, int qt, int rn, int imm) {
    // LDR Qd, [Xn, #imm] - Load 128-bit into NEON register
    // Instruction encoding: 0011 1101 1100 0000 0000 0000 0000 0000
    // + (imm/16 << 10) + (rn << 5) + qt
    uint32_t insn = 0x3dc00000 | ((imm >> 4) << 10) | (rn << 5) | qt;
    emit_u32(jit, insn);
}

// Emit NEON 128-bit store (STR Qd, [Xn, #imm])
static void emit_str_q_imm(vfm_jit_arm64_t *jit, int qt, int rn, int imm) {
    // STR Qd, [Xn, #imm] - Store 128-bit from NEON register
    // Instruction encoding: 0011 1101 1000 0000 0000 0000 0000 0000
    // + (imm/16 << 10) + (rn << 5) + qt
    uint32_t insn = 0x3d800000 | ((imm >> 4) << 10) | (rn << 5) | qt;
    emit_u32(jit, insn);
}

// Emit NEON 128-bit comparison (CMEQ Vd.16B, Vn.16B, Vm.16B)
static void emit_cmeq_v16b(vfm_jit_arm64_t *jit, int vd, int vn, int vm) {
    // CMEQ Vd.16B, Vn.16B, Vm.16B - Compare equal (128-bit vectors)
    uint32_t insn = 0x6e208c00 | (vm << 16) | (vn << 5) | vd;
    emit_u32(jit, insn);
}

// Emit ADDP to reduce 128-bit comparison result to scalar
static void emit_addp_v16b(vfm_jit_arm64_t *jit, int vd, int vn) {
    // ADDP Vd.16B, Vn.16B, Vn.16B - Pairwise add to reduce to scalar
    uint32_t insn = 0x6e20bc00 | (vn << 16) | (vn << 5) | vd;
    emit_u32(jit, insn);
}

// Emit ADDV to efficiently reduce vector to scalar (single instruction)
static void emit_addv_v16b(vfm_jit_arm64_t *jit, int vd, int vn) {
    // ADDV Bd, Vn.16B - sum all 16 bytes to single byte in Bd
    uint32_t insn = 0x4e31b800 | (vn << 5) | vd;
    emit_u32(jit, insn);
}

// Emit scaled load for 128-bit stack access (single instruction)
static void emit_ldr_q_scaled(vfm_jit_arm64_t *jit, int qt, int base, int index) {
    // LDR Qd, [Xbase, Xindex, LSL #4] - load with scaled index
    uint32_t insn = 0x3cc00000 | (1 << 12) | (index << 16) | (base << 5) | qt;
    emit_u32(jit, insn);
}

// Emit scaled store for 128-bit stack access (single instruction)
static void emit_str_q_scaled(vfm_jit_arm64_t *jit, int qt, int base, int index) {
    // STR Qd, [Xbase, Xindex, LSL #4] - store with scaled index
    uint32_t insn = 0x3c800000 | (1 << 12) | (index << 16) | (base << 5) | qt;
    emit_u32(jit, insn);
}

// Emit prefetch instruction for memory optimization
static void emit_prfm(vfm_jit_arm64_t *jit, int type, int rn, int offset) {
    // PRFM type, [Xn, #offset] - prefetch memory
    // Type: 0=PLDL1KEEP, 1=PLDL1STRM, 2=PLDL2KEEP, 3=PLDL2STRM
    uint32_t insn = 0xf9800000 | (type << 0) | ((offset >> 3) << 10) | (rn << 5);
    emit_u32(jit, insn);
}

// NEON parallel load/store operations for optimized stack bandwidth

// Emit LDP for Q-registers (load pair of 128-bit values)
static void emit_ldp_q(vfm_jit_arm64_t *jit, int qt1, int qt2, int rn, int imm) {
    // LDP Qd1, Qd2, [Xn, #imm] - Load pair of 128-bit values
    // Allows loading 2x128 = 256 bits in a single instruction
    // imm must be multiple of 32 bytes (range: -1024 to +1008)
    uint32_t insn = 0xad400000 | ((imm >> 4) << 15) | (qt2 << 10) | (rn << 5) | qt1;
    emit_u32(jit, insn);
}

// Emit STP for Q-registers (store pair of 128-bit values)
static void emit_stp_q(vfm_jit_arm64_t *jit, int qt1, int qt2, int rn, int imm) {
    // STP Qd1, Qd2, [Xn, #imm] - Store pair of 128-bit values
    // Allows storing 2x128 = 256 bits in a single instruction
    // imm must be multiple of 32 bytes (range: -1024 to +1008)
    uint32_t insn = 0xad000000 | ((imm >> 4) << 15) | (qt2 << 10) | (rn << 5) | qt1;
    emit_u32(jit, insn);
}

// Emit LDP with post-increment for Q-registers
static void emit_ldp_q_post(vfm_jit_arm64_t *jit, int qt1, int qt2, int rn, int imm) {
    // LDP Qd1, Qd2, [Xn], #imm - Load pair with post-increment
    // Useful for streaming operations through stack regions
    uint32_t insn = 0xacc00000 | ((imm >> 4) << 15) | (qt2 << 10) | (rn << 5) | qt1;
    emit_u32(jit, insn);
}

// Emit STP with pre-decrement for Q-registers
static void emit_stp_q_pre(vfm_jit_arm64_t *jit, int qt1, int qt2, int rn, int imm) {
    // STP Qd1, Qd2, [Xn, #imm]! - Store pair with pre-decrement
    // Useful for pushing multiple values to stack efficiently
    uint32_t insn = 0xad800000 | ((imm >> 4) << 15) | (qt2 << 10) | (rn << 5) | qt1;
    emit_u32(jit, insn);
}

// Optimized bulk stack operations using NEON parallelism

// Bulk load multiple 128-bit values from stack (2 at a time for better bandwidth)
static void emit_bulk_stack128_load(vfm_jit_arm64_t *jit, int count, int base_reg, int offset) {
    // Load 'count' 128-bit values using LDP instructions for optimal memory bandwidth
    // Uses Q0-Q7 as temporary registers
    int pairs = count / 2;
    int remainder = count % 2;
    
    for (int i = 0; i < pairs; i++) {
        int q1 = (i * 2) % 8;     // Cycle through Q0-Q7
        int q2 = (i * 2 + 1) % 8;
        emit_ldp_q(jit, q1, q2, base_reg, offset + i * 32);
    }
    
    // Handle odd count with single LDR
    if (remainder) {
        int q_reg = (pairs * 2) % 8;
        emit_ldr_q_imm(jit, q_reg, base_reg, offset + pairs * 32);
    }
}

// Bulk store multiple 128-bit values to stack (2 at a time for better bandwidth)
static void emit_bulk_stack128_store(vfm_jit_arm64_t *jit, int count, int base_reg, int offset) {
    // Store 'count' 128-bit values using STP instructions for optimal memory bandwidth
    // Uses Q0-Q7 as source registers
    int pairs = count / 2;
    int remainder = count % 2;
    
    for (int i = 0; i < pairs; i++) {
        int q1 = (i * 2) % 8;     // Cycle through Q0-Q7
        int q2 = (i * 2 + 1) % 8;
        emit_stp_q(jit, q1, q2, base_reg, offset + i * 32);
    }
    
    // Handle odd count with single STR
    if (remainder) {
        int q_reg = (pairs * 2) % 8;
        emit_str_q_imm(jit, q_reg, base_reg, offset + pairs * 32);
    }
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
    // stp x23, x24, [sp, #-16]!
    emit_u32(jit, 0xa9bf63f7);
}

// Emit function epilogue
static void emit_epilogue(vfm_jit_arm64_t *jit) {
    // ldp x23, x24, [sp], #16
    emit_u32(jit, 0xa8c163f7);
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
    // X22 = 128-bit stack pointer
    // X23 = 128-bit stack base pointer
    // Q0-Q7 = NEON 128-bit registers for IPv6 operations
    
    // Initialize VM registers
    emit_ldr_imm(&jit, ARM64_X21, ARM64_X0, 8);  // Load stack pointer
    emit_mov_imm(&jit, ARM64_X19, 0);            // Initialize SP
    emit_mov_imm(&jit, ARM64_X20, 0);            // Initialize PC
    
    // Initialize 128-bit stack registers
    emit_ldr_imm(&jit, ARM64_X23, ARM64_X0, 160); // Load 128-bit stack base (stack128 field offset)
    emit_ldr_imm(&jit, ARM64_X22, ARM64_X0, 172); // Load current sp128 value (sp128 field offset)
    
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
            
            case VFM_LD128: {
                // Optimized 128-bit load from packet (IPv6 address) with prefetching
                uint16_t offset = *(uint16_t*)&program[pc];
                pc += 2;
                
                // Calculate packet address with bounds check
                emit_mov_imm(&jit, ARM64_X3, offset);             // Load offset into X3
                emit_add_reg(&jit, ARM64_X3, ARM64_X1, ARM64_X3); // packet + offset  
                // TODO: Add proper bounds checking for offset + 16 > packet_len
                
                // Prefetch potential next IPv6 data for cache optimization
                emit_prfm(&jit, 0, ARM64_X3, 64);                 // PLDL1KEEP [X3, #64]
                
                // Load 128-bit value into Q0 from packet[offset] 
                emit_ldr_q_imm(&jit, ARM64_Q0, ARM64_X3, 0);
                
                // Push to 128-bit stack using optimized scaled store
                emit_mov_imm(&jit, ARM64_X4, 1);                   // Increment value
                emit_add_reg(&jit, ARM64_X22, ARM64_X22, ARM64_X4); // sp128++
                emit_str_q_scaled(&jit, ARM64_Q0, ARM64_X23, ARM64_X22); // stack128[sp128] = Q0
                break;
            }
            
            case VFM_EQ128: {
                // Optimized 128-bit comparison with NEON vectorized operations
                
                // Load operands directly with scaled addressing (parallel execution possible)
                emit_sub_imm(&jit, ARM64_X22, ARM64_X22, 1);       // sp128-- (for second operand)
                emit_ldr_q_scaled(&jit, ARM64_Q1, ARM64_X23, ARM64_X22); // Q1 = stack128[sp128] (top)
                emit_sub_imm(&jit, ARM64_X22, ARM64_X22, 1);       // sp128-- (for first operand)  
                emit_ldr_q_scaled(&jit, ARM64_Q0, ARM64_X23, ARM64_X22); // Q0 = stack128[sp128-1] (second)
                
                // Vectorized 128-bit comparison (CMEQ produces all-1s for equal bytes, all-0s for unequal)
                emit_cmeq_v16b(&jit, ARM64_Q2, ARM64_Q0, ARM64_Q1);
                
                // Efficient single-instruction reduction: sum all bytes to check if all are 0xFF
                emit_addv_v16b(&jit, ARM64_Q3, ARM64_Q2);          // Sum all 16 bytes into B3
                
                // Extract single byte result and check if it equals 16*255 = 4080 (0xFF0)
                emit_umov_x(&jit, ARM64_X3, ARM64_Q3, 0);          // Extract summed byte to X3
                
                // Create comparison result: X3 = (X3 == 4080) ? 1 : 0
                emit_mov_imm(&jit, ARM64_X4, 4080);               // Expected value for all equal
                // CMP X3, X4; CSET X3, EQ (sets X3 = 1 if equal, 0 if not)
                emit_u32(&jit, 0xeb04007f);                       // CMP X3, X4
                emit_u32(&jit, 0x9a9f0063);                       // CSET X3, EQ
                
                // Push result to 64-bit stack efficiently
                emit_mov_imm(&jit, ARM64_X4, 1);                  // Prepare increment
                emit_add_reg(&jit, ARM64_X19, ARM64_X19, ARM64_X4); // sp++ (increment stack pointer)
                emit_str_imm(&jit, ARM64_X3, ARM64_X21, 0);       // stack[sp] = result
                break;
            }
            
            // New optimized operations using NEON parallel load/store
            
            case VFM_BULK_LOAD128: {
                // Bulk load multiple 128-bit values using NEON LDP for optimal bandwidth
                uint8_t count = program[pc++];  // Number of 128-bit values to load
                uint16_t offset = *(uint16_t*)&program[pc]; // Starting packet offset
                pc += 2;
                
                if (count > 8) count = 8;  // Limit to available Q-registers
                
                // Calculate packet address
                emit_mov_imm(&jit, ARM64_X3, offset);
                emit_add_reg(&jit, ARM64_X3, ARM64_X1, ARM64_X3); // packet + offset
                
                // Prefetch multiple cache lines for bulk access
                for (int i = 0; i < (count + 3) / 4; i++) {
                    emit_prfm(&jit, 0, ARM64_X3, i * 64); // PLDL1KEEP every 64 bytes
                }
                
                // Use bulk load function with NEON parallelism
                emit_bulk_stack128_load(&jit, count, ARM64_X3, 0);
                
                // Update 128-bit stack pointer (sp128 += count)
                emit_mov_imm(&jit, ARM64_X4, count);
                emit_add_reg(&jit, ARM64_X22, ARM64_X22, ARM64_X4);
                
                // Store loaded values to 128-bit stack using bulk store
                emit_bulk_stack128_store(&jit, count, ARM64_X23, 
                    (int)((count - 1) * -16)); // Negative offset to store at stack top
                break;
            }
            
            case VFM_PARALLEL_EQ128: {
                // Parallel comparison of multiple 128-bit values using NEON LDP
                uint8_t count = program[pc++];  // Number of pairs to compare
                
                if (count > 4) count = 4;  // Limit to available Q-register pairs
                
                // Load pairs of 128-bit values from stack using LDP for bandwidth
                for (int i = 0; i < count; i++) {
                    // Load pair (2 values) for comparison
                    emit_sub_imm(&jit, ARM64_X22, ARM64_X22, 2); // sp128 -= 2
                    emit_ldp_q(&jit, ARM64_Q0 + i*2, ARM64_Q1 + i*2, ARM64_X23, 
                        (int)(ARM64_X22 * 16)); // Load pair from stack
                    
                    // Vectorized comparison
                    emit_cmeq_v16b(&jit, ARM64_Q4 + i, ARM64_Q0 + i*2, ARM64_Q1 + i*2);
                    
                    // Reduce to scalar
                    emit_addv_v16b(&jit, ARM64_Q4 + i, ARM64_Q4 + i);
                }
                
                // Combine results and push to 64-bit stack
                for (int i = 0; i < count; i++) {
                    emit_umov_x(&jit, ARM64_X3 + i, ARM64_Q4 + i, 0);
                    emit_mov_imm(&jit, ARM64_X4, 4080); // Expected value for equality
                    // Compare and set result
                    emit_u32(&jit, 0xeb04007f + (i << 5)); // CMP X(3+i), X4
                    emit_u32(&jit, 0x9a9f0063 + (i << 5)); // CSET X(3+i), EQ
                    
                    // Push result to stack
                    emit_mov_imm(&jit, ARM64_X4, 1);
                    emit_add_reg(&jit, ARM64_X19, ARM64_X19, ARM64_X4); // sp++
                    emit_str_imm(&jit, ARM64_X3 + i, ARM64_X21, i * 8); // stack[sp+i] = result
                }
                break;
            }
            
            case VFM_STACK_PREFETCH: {
                // Prefetch upcoming stack region to optimize cache performance
                uint8_t depth = program[pc++];  // How many cache lines to prefetch
                
                // Prefetch both 64-bit and 128-bit stacks
                for (int i = 0; i < depth && i < 8; i++) {
                    // Prefetch 64-bit stack
                    emit_prfm(&jit, 0, ARM64_X21, i * 64); // PLDL1KEEP
                    // Prefetch 128-bit stack
                    emit_prfm(&jit, 0, ARM64_X23, i * 64); // PLDL1KEEP
                }
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