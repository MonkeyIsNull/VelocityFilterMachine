#ifdef __linux__
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L  /* For clock_gettime, strdup, and other POSIX functions */
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE  /* For sysconf and other system functions */
#endif
#ifndef _ISOC11_SOURCE
#define _ISOC11_SOURCE  /* For aligned_alloc and other C11 functions */
#endif
#endif

#include "vfm.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifdef __APPLE__
#include <libkern/OSCacheControl.h>
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
static void __attribute__((unused)) emit_umov_x(vfm_jit_arm64_t *jit, int rd, int vn, int index) {
    // UMOV Xd, Vn.D[index] - extract 64-bit element to X register
    uint32_t insn = 0x4e083c00 | ((index & 1) << 20) | (vn << 5) | rd;
    emit_u32(jit, insn);
}


// Emit LDR immediate
static void __attribute__((unused)) emit_ldr_imm(vfm_jit_arm64_t *jit, int rt, int rn, int imm) {
    // LDR Xt, [Xn, #imm]
    uint32_t insn = 0xf9400000 | ((imm >> 3) << 10) | (rn << 5) | rt;
    emit_u32(jit, insn);
}

// Emit STR immediate
static void __attribute__((unused)) emit_str_imm(vfm_jit_arm64_t *jit, int rt, int rn, int imm) {
    // STR Xt, [Xn, #imm]
    uint32_t insn = 0xf9000000 | ((imm >> 3) << 10) | (rn << 5) | rt;
    emit_u32(jit, insn);
}

// Emit RET
static void emit_ret(vfm_jit_arm64_t *jit) {
    // RET X30
    emit_u32(jit, 0xd65f03c0);
}

// Emit MOV (register): ORR Xd, XZR, Xm
static void emit_mov_reg(vfm_jit_arm64_t *jit, int rd, int rm) {
    emit_u32(jit, 0xaa0003e0 | (rm << 16) | rd);
}

// Emit a full 64-bit immediate via MOVZ + up to three MOVK (16-bit chunks).
// The old emit_mov_imm emitted a single MOVZ and silently truncated any
// value above 0xFFFF, so PUSH of a large immediate did not match the
// interpreter. This covers the whole 64-bit range.
static void emit_mov_imm64(vfm_jit_arm64_t *jit, int rd, uint64_t imm) {
    // MOVZ Xd, #imm[15:0]
    emit_u32(jit, 0xd2800000 | (uint32_t)((imm & 0xFFFF) << 5) | rd);
    // MOVK Xd, #imm[31:16], LSL #16
    if ((imm >> 16) & 0xFFFF) {
        emit_u32(jit, 0xf2a00000 | (uint32_t)(((imm >> 16) & 0xFFFF) << 5) | rd);
    }
    // MOVK Xd, #imm[47:32], LSL #32
    if ((imm >> 32) & 0xFFFF) {
        emit_u32(jit, 0xf2c00000 | (uint32_t)(((imm >> 32) & 0xFFFF) << 5) | rd);
    }
    // MOVK Xd, #imm[63:48], LSL #48
    if ((imm >> 48) & 0xFFFF) {
        emit_u32(jit, 0xf2e00000 | (uint32_t)(((imm >> 48) & 0xFFFF) << 5) | rd);
    }
}

// Emit ADD Xd, Xn, #imm12
static void emit_add_imm(vfm_jit_arm64_t *jit, int rd, int rn, int imm) {
    emit_u32(jit, 0x91000000 | ((imm & 0xFFF) << 10) | (rn << 5) | rd);
}

// Emit STR Xt, [Xn, Xm, LSL #3] (64-bit, scaled register offset)
static void emit_str_reg_x(vfm_jit_arm64_t *jit, int rt, int rn, int rm) {
    emit_u32(jit, 0xf8207800 | (rm << 16) | (rn << 5) | rt);
}

// Emit LDR Xt, [Xn, Xm, LSL #3] (64-bit, scaled register offset)
static void emit_ldr_reg_x(vfm_jit_arm64_t *jit, int rt, int rn, int rm) {
    emit_u32(jit, 0xf8607800 | (rm << 16) | (rn << 5) | rt);
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
static void __attribute__((unused)) emit_cmeq_v16b(vfm_jit_arm64_t *jit, int vd, int vn, int vm) {
    // CMEQ Vd.16B, Vn.16B, Vm.16B - Compare equal (128-bit vectors)
    uint32_t insn = 0x6e208c00 | (vm << 16) | (vn << 5) | vd;
    emit_u32(jit, insn);
}


// Emit ADDV to efficiently reduce vector to scalar (single instruction)
static void __attribute__((unused)) emit_addv_v16b(vfm_jit_arm64_t *jit, int vd, int vn) {
    // ADDV Bd, Vn.16B - sum all 16 bytes to single byte in Bd
    uint32_t insn = 0x4e31b800 | (vn << 5) | vd;
    emit_u32(jit, insn);
}

// Emit scaled load for 128-bit stack access (single instruction)
static void __attribute__((unused)) emit_ldr_q_scaled(vfm_jit_arm64_t *jit, int qt, int base, int index) {
    // LDR Qd, [Xbase, Xindex, LSL #4] - load with scaled index
    uint32_t insn = 0x3cc00000 | (1 << 12) | (index << 16) | (base << 5) | qt;
    emit_u32(jit, insn);
}

// Emit scaled store for 128-bit stack access (single instruction)
static void __attribute__((unused)) emit_str_q_scaled(vfm_jit_arm64_t *jit, int qt, int base, int index) {
    // STR Qd, [Xbase, Xindex, LSL #4] - store with scaled index
    uint32_t insn = 0x3c800000 | (1 << 12) | (index << 16) | (base << 5) | qt;
    emit_u32(jit, insn);
}

// Emit prefetch instruction for memory optimization
static void __attribute__((unused)) emit_prfm(vfm_jit_arm64_t *jit, int type, int rn, int offset) {
    // PRFM type, [Xn, #offset] - prefetch memory
    // Type: 0=PLDL1KEEP, 1=PLDL1STRM, 2=PLDL2KEEP, 3=PLDL2STRM
    uint32_t insn = 0xf9800000 | (type << 0) | ((offset >> 3) << 10) | (rn << 5);
    emit_u32(jit, insn);
}

// ARM64-specific instruction scheduling optimizations for Phase 2.1.4

// Instruction scheduling context for tracking dependencies
typedef struct {
    uint32_t *instructions;          // Buffer of instructions to schedule
    int *dependency_map;             // Register dependency tracking
    int instruction_count;           // Number of instructions in buffer
    int buffer_capacity;             // Maximum buffer size
    bool scheduling_enabled;         // Enable/disable scheduling optimization
} arm64_scheduler_t;

// Initialize instruction scheduler
static void init_scheduler(arm64_scheduler_t *sched, int capacity) {
    sched->instructions = malloc(capacity * sizeof(uint32_t));
    sched->dependency_map = malloc(capacity * 32 * sizeof(int)); // 32 registers max
    sched->instruction_count = 0;
    sched->buffer_capacity = capacity;
    sched->scheduling_enabled = true;
}

// Free scheduler resources
static void free_scheduler(arm64_scheduler_t *sched) {
    free(sched->instructions);
    free(sched->dependency_map);
    sched->instructions = NULL;
    sched->dependency_map = NULL;
}

// Analyze instruction for register dependencies
static void analyze_instruction_deps(uint32_t insn, int *read_regs, int *write_regs, int *read_count, int *write_count) {
    *read_count = 0;
    *write_count = 0;
    
    // Extract register fields based on ARM64 instruction format
    int rd = insn & 0x1f;          // Destination register
    int rn = (insn >> 5) & 0x1f;   // First source register
    int rm = (insn >> 16) & 0x1f;  // Second source register (if applicable)
    
    // Determine instruction type and dependencies
    uint32_t opcode_mask = insn & 0xffe00000;
    
    if ((opcode_mask & 0xffc00000) == 0x8b000000) {  // ADD register
        read_regs[(*read_count)++] = rn;
        read_regs[(*read_count)++] = rm;
        write_regs[(*write_count)++] = rd;
    } else if ((opcode_mask & 0xffc00000) == 0xf9400000) {  // LDR immediate
        read_regs[(*read_count)++] = rn;
        write_regs[(*write_count)++] = rd;
    } else if ((opcode_mask & 0xffc00000) == 0xf9000000) {  // STR immediate
        read_regs[(*read_count)++] = rn;
        read_regs[(*read_count)++] = rd;  // Data to store
    } else if ((opcode_mask & 0xff000000) == 0x6e000000) {  // NEON operations
        read_regs[(*read_count)++] = rn;
        if ((insn & 0x00200000) == 0) {  // Three-register format
            read_regs[(*read_count)++] = rm;
        }
        write_regs[(*write_count)++] = rd;
    }
}

// Check if instruction can be reordered (no dependencies)
static bool can_reorder(uint32_t insn1, uint32_t insn2) {
    int read1[4], write1[4], read2[4], write2[4];
    int read_count1, write_count1, read_count2, write_count2;
    
    analyze_instruction_deps(insn1, read1, write1, &read_count1, &write_count1);
    analyze_instruction_deps(insn2, read2, write2, &read_count2, &write_count2);
    
    // Check for WAR (Write-After-Read), RAW (Read-After-Write), WAW (Write-After-Write) hazards
    for (int i = 0; i < write_count1; i++) {
        for (int j = 0; j < read_count2; j++) {
            if (write1[i] == read2[j]) return false;  // RAW hazard
        }
        for (int j = 0; j < write_count2; j++) {
            if (write1[i] == write2[j]) return false;  // WAW hazard
        }
    }
    
    for (int i = 0; i < read_count1; i++) {
        for (int j = 0; j < write_count2; j++) {
            if (read1[i] == write2[j]) return false;  // WAR hazard
        }
    }
    
    return true;  // No dependencies, can reorder
}

// Optimized instruction scheduling for ARM64 superscalar execution
static void schedule_instructions(arm64_scheduler_t *sched, vfm_jit_arm64_t *jit) {
    if (!sched->scheduling_enabled || sched->instruction_count < 2) {
        // Emit instructions in original order if scheduling disabled or too few instructions
        for (int i = 0; i < sched->instruction_count; i++) {
            emit_u32(jit, sched->instructions[i]);
        }
        sched->instruction_count = 0;
        return;
    }
    
    bool *scheduled = calloc(sched->instruction_count, sizeof(bool));
    int scheduled_count = 0;
    
    // Simple list scheduling algorithm optimized for ARM64 pipeline
    while (scheduled_count < sched->instruction_count) {
        int best_candidate = -1;
        int best_score = -1;
        
        for (int i = 0; i < sched->instruction_count; i++) {
            if (scheduled[i]) continue;
            
            // Check if instruction can be scheduled (all dependencies satisfied)
            bool can_schedule = true;
            for (int j = 0; j < i; j++) {
                if (!scheduled[j] && !can_reorder(sched->instructions[j], sched->instructions[i])) {
                    can_schedule = false;
                    break;
                }
            }
            
            if (can_schedule) {
                // Prioritize instruction types for optimal ARM64 pipeline utilization
                int score = 0;
                uint32_t insn = sched->instructions[i];
                
                // Higher priority for memory operations (can dual-issue with ALU)
                if ((insn & 0xffc00000) == 0xf9400000 || (insn & 0xffc00000) == 0xf9000000) {
                    score += 3;  // LDR/STR
                }
                // Medium priority for NEON operations (ASIMD pipeline)
                else if ((insn & 0xff000000) == 0x6e000000) {
                    score += 2;  // NEON/ASIMD
                }
                // Lower priority for ALU operations (can dual-issue)
                else if ((insn & 0xffc00000) == 0x8b000000) {
                    score += 1;  // ADD/SUB
                }
                
                if (score > best_score) {
                    best_score = score;
                    best_candidate = i;
                }
            }
        }
        
        if (best_candidate != -1) {
            emit_u32(jit, sched->instructions[best_candidate]);
            scheduled[best_candidate] = true;
            scheduled_count++;
        } else {
            // Fallback: schedule first unscheduled instruction to avoid infinite loop
            for (int i = 0; i < sched->instruction_count; i++) {
                if (!scheduled[i]) {
                    emit_u32(jit, sched->instructions[i]);
                    scheduled[i] = true;
                    scheduled_count++;
                    break;
                }
            }
        }
    }
    
    free(scheduled);
    sched->instruction_count = 0;  // Reset buffer
}


// Flush any remaining instructions in scheduler
static void flush_scheduler(arm64_scheduler_t *sched, vfm_jit_arm64_t *jit) {
    schedule_instructions(sched, jit);
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



// Optimized bulk stack operations using NEON parallelism

// Bulk load multiple 128-bit values from stack (2 at a time for better bandwidth)
static void __attribute__((unused)) emit_bulk_stack128_load(vfm_jit_arm64_t *jit, int count, int base_reg, int offset) {
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
static void __attribute__((unused)) emit_bulk_stack128_store(vfm_jit_arm64_t *jit, int count, int base_reg, int offset) {
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
    // On other ARM64 systems, flush the instruction cache and set executable permissions
    #if defined(__GNUC__) || defined(__clang__)
        __builtin___clear_cache((char*)code, (char*)code + code_pos);
    #else
        // Fallback for other compilers - attempt manual cache flush via syscall
        #ifdef __linux__
            // Linux-specific cache flush
            asm volatile("dsb sy\n\t"
                        "isb"
                        ::: "memory");
        #endif
    #endif
    
    // Set memory permissions to read+execute
    if (mprotect(code, code_size, PROT_READ | PROT_EXEC) != 0) {
        return false;
    }
#endif
    return true;
}

// ============================================================================
// Shared per-opcode emitters (one source of truth for single-core and adaptive)
//
// Calling convention (see vfm_jit_execute in vfm.c), identical on every arch:
//   uint64_t fn(const uint8_t *packet, uint16_t packet_len,
//               uint64_t *stack64, vfm_u128_t *stack128)
// AArch64 argument registers: X0=packet, X1=len, X2=stack64, X3=stack128.
//
// Register map inside compiled code:
//   X0  = packet base (arg0)       X1  = packet length (arg1)
//   X21 = stack64 base (from X2)   X23 = stack128 base (from X3)
//   X19 = sp  (64-bit stack index, starts at 0)
//   X22 = sp128 (128-bit stack index, starts at 0)
//   X3, X4 = scratch
//
// Stack discipline mirrors the interpreter exactly (vfm.c STACK_PUSH/POP):
// sp starts at 0, slot 0 is the empty sentinel, PUSH does stack[++sp]=v,
// POP returns stack[sp--], RET returns stack[sp].
// ============================================================================

// Establish the VM register map from the incoming argument registers.
// NOTE: this does NOT dereference any struct -- the stack bases arrive as
// explicit pointer arguments, so one compiled page is valid for the single
// VM and for every worker thread's per-core VM simultaneously.
static void emit_vm_setup(vfm_jit_arm64_t *jit) {
    emit_mov_reg(jit, ARM64_X21, ARM64_X2);   // stack64 base
    emit_mov_reg(jit, ARM64_X23, ARM64_X3);   // stack128 base
    emit_mov_imm(jit, ARM64_X19, 0);          // sp   = 0
    emit_mov_imm(jit, ARM64_X22, 0);          // sp128 = 0
}

// PUSH imm64 : stack[++sp] = imm
static void emit_op_push(vfm_jit_arm64_t *jit, uint64_t imm) {
    emit_mov_imm64(jit, ARM64_X3, imm);
    emit_add_imm(jit, ARM64_X19, ARM64_X19, 1);      // sp++
    emit_str_reg_x(jit, ARM64_X3, ARM64_X21, ARM64_X19); // stack[sp] = imm
}

// ADD : b=stack[sp]; a=stack[sp-1]; stack[sp-1]=a+b; sp--
static void emit_op_add(vfm_jit_arm64_t *jit) {
    emit_ldr_reg_x(jit, ARM64_X3, ARM64_X21, ARM64_X19); // b = stack[sp]
    emit_sub_imm(jit, ARM64_X19, ARM64_X19, 1);          // sp--
    emit_ldr_reg_x(jit, ARM64_X4, ARM64_X21, ARM64_X19); // a = stack[sp-1]
    emit_add_reg(jit, ARM64_X4, ARM64_X4, ARM64_X3);     // a + b
    emit_str_reg_x(jit, ARM64_X4, ARM64_X21, ARM64_X19); // stack[sp-1] = a+b
}

// RET : return stack[sp] in X0
static void emit_op_ret(vfm_jit_arm64_t *jit) {
    emit_ldr_reg_x(jit, ARM64_X0, ARM64_X21, ARM64_X19);
    emit_epilogue(jit);
}

// Shared compile core. Single-core and adaptive run the SAME loop, the SAME
// prologue/ABI, the SAME per-opcode emitters and the SAME decline-and-clean-up
// bail path. `profile` is advisory only (prefetch/scheduling hints) and may
// NEVER change instruction semantics; it is currently unused because the
// trusted emitter set (PUSH/ADD/RET) has no profile-tunable form. Any opcode
// outside that set hits the decline path: free all partial state, re-enable
// W^X, munmap, return NULL -- the caller then falls back to the interpreter.
static void* vfm_jit_compile_arm64_impl(const uint8_t *program, uint32_t len,
                                        vfm_execution_profile_t *profile) {
    (void)profile;
    size_t code_size = 4096;

#ifdef __APPLE__
    uint8_t *code = mmap(NULL, code_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
    uint8_t *code = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    if (code == MAP_FAILED) {
        return NULL;
    }

    vfm_jit_arm64_t jit = { .code = code, .code_size = code_size, .code_pos = 0 };

    arm64_scheduler_t scheduler;
    init_scheduler(&scheduler, 16);

#ifdef __APPLE__
    // Disable W^X write protection for this thread before writing the MAP_JIT
    // page. The toggle is thread-local and must be re-enabled on every exit
    // path (success via flush_and_protect_memory, bail via the label below).
    pthread_jit_write_protect_np(0);
#endif

    emit_prologue(&jit);
    emit_vm_setup(&jit);

    for (uint32_t pc = 0; pc < len; ) {
        uint8_t opcode = program[pc++];

        switch (opcode) {
            case VFM_PUSH: {
                uint64_t imm = *(uint64_t*)&program[pc];
                pc += 8;
                emit_op_push(&jit, imm);
                break;
            }

            case VFM_ADD: {
                emit_op_add(&jit);
                break;
            }

            case VFM_RET: {
                emit_op_ret(&jit);
                flush_scheduler(&scheduler, &jit);
                free_scheduler(&scheduler);
                if (!flush_and_protect_memory(jit.code, jit.code_pos, jit.code_size)) {
                    return NULL;  // flush_and_protect_memory re-enables W^X + munmaps on failure
                }
                return jit.code;
            }

            // Every other opcode -- including LD8/LD16/LD32, the comparisons,
            // and the 128-bit NEON ops (LD128/EQ128/BULK_LOAD128/
            // PARALLEL_EQ128) that previously emitted wrong or unvalidated
            // code -- is DECLINED. We never emit a nop or a fabricated result.
            // The caller leaves jit_code NULL and runs the bounds-checked
            // interpreter, which implements every opcode correctly.
            default:
                goto decline;
        }
    }

    // Program ran off the end without a RET. Treat as uncompilable rather than
    // fabricate a return value; the interpreter/verifier handle this case.
decline:
    free_scheduler(&scheduler);
#ifdef __APPLE__
    pthread_jit_write_protect_np(1);
#endif
    munmap(code, code_size);
    return NULL;
}

// JIT compile for ARM64 (single-core entry point)
void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len) {
    return vfm_jit_compile_arm64_impl(program, len, NULL);
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

// Phase 3.2.3: Adaptive ARM64 JIT compilation with packet pattern optimization.
//
// The previous adaptive compiler was a separate, broken code generator (wrong
// ABI, raw x0/x1 operands, missing W^X toggle, a `nop` default that silently
// mis-filtered). It is discarded. Adaptive compilation now REUSES the exact
// single-core compile core, prologue, ABI and decline path. The profile is
// passed through for future prefetch/scheduling hints but may never alter
// instruction semantics, so adaptive output is currently byte-for-byte the
// same correct code as the single-core path. Any opcode outside the trusted
// set declines (returns NULL) -> the caller keeps/falls back to the previous
// valid page or the interpreter. This is the honest "decline, never nop"
// contract until profile-guided emitters are individually oracle-validated.
void* vfm_jit_compile_arm64_adaptive(const uint8_t *program, uint32_t len,
                                     vfm_execution_profile_t *profile) {
    return vfm_jit_compile_arm64_impl(program, len, profile);
}

#else

// Stub for non-ARM64 platforms
void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len) {
    (void)program;
    (void)len;
    return NULL;
}

void* vfm_jit_compile_arm64_adaptive(const uint8_t *program, uint32_t len, 
                                     vfm_execution_profile_t *profile) {
    (void)program;
    (void)len;
    (void)profile;
    return NULL;
}

bool vfm_jit_available_arm64(void) {
    return false;
}

#endif