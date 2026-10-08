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
#include <unistd.h>

#ifdef __x86_64__
#include <cpuid.h>
#include <immintrin.h>
#endif

// x86-64 registers
#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8  8
#define R9  9
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15

// AVX2/YMM registers for Phase 2.2 optimizations
#define YMM0  0
#define YMM1  1
#define YMM2  2
#define YMM3  3
#define YMM4  4
#define YMM5  5
#define YMM6  6
#define YMM7  7
#define YMM8  8
#define YMM9  9
#define YMM10 10
#define YMM11 11
#define YMM12 12
#define YMM13 13
#define YMM14 14
#define YMM15 15

// CPU capabilities for Phase 2.2 AVX2 optimizations
typedef struct x86_64_caps {
    bool has_avx2;          // AVX2 support
    bool has_bmi1;          // BMI1 instructions
    bool has_bmi2;          // BMI2 instructions  
    bool has_popcnt;        // POPCNT instruction
    bool has_lzcnt;         // LZCNT instruction
    bool has_prefetch;      // Prefetch instructions
    enum {
        CPU_VENDOR_UNKNOWN,
        CPU_VENDOR_INTEL,
        CPU_VENDOR_AMD
    } vendor;               // CPU vendor for instruction preferences
} x86_64_caps_t;

// x86-64 JIT compiler state
typedef struct x86_64_jit {
    uint8_t *code;          // Executable memory
    size_t code_size;       // Total size of allocated memory
    size_t code_pos;        // Current position in code buffer
    uint32_t stack_depth;   // Current stack depth
    uint8_t stack_regs[16]; // Register allocation for stack simulation
    uint32_t next_reg;      // Next available register
    uint32_t *labels;       // Jump target labels
    uint32_t label_count;   // Number of labels
    x86_64_caps_t caps;     // CPU capabilities
    bool use_avx2;          // Use AVX2 optimizations
} x86_64_jit_t;

// x86-64 instruction encoders
static void emit_byte(x86_64_jit_t *jit, uint8_t byte);
static void emit_word(x86_64_jit_t *jit, uint16_t word);
static void emit_dword(x86_64_jit_t *jit, uint32_t dword);
static void emit_qword(x86_64_jit_t *jit, uint64_t qword);

// Register management
static uint8_t alloc_reg(x86_64_jit_t *jit);
static void free_reg(x86_64_jit_t *jit, uint8_t reg);

// x86-64 instruction generation
static void emit_mov_reg_imm64(x86_64_jit_t *jit, uint8_t reg, uint64_t imm);
static void emit_mov_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void __attribute__((unused)) emit_mov_reg_mem(x86_64_jit_t *jit, uint8_t reg, uint8_t base, int32_t offset);
static void __attribute__((unused)) emit_mov_mem_reg(x86_64_jit_t *jit, uint8_t base, int32_t offset, uint8_t reg);
static void emit_add_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_sub_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_mul_reg(x86_64_jit_t *jit, uint8_t reg);
static void __attribute__((unused)) emit_div_reg(x86_64_jit_t *jit, uint8_t reg);
static void emit_and_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_or_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_xor_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_shl_reg_cl(x86_64_jit_t *jit, uint8_t reg);
static void emit_shr_reg_cl(x86_64_jit_t *jit, uint8_t reg);
static void emit_not_reg(x86_64_jit_t *jit, uint8_t reg);
static void emit_neg_reg(x86_64_jit_t *jit, uint8_t reg);
static void emit_cmp_reg_reg(x86_64_jit_t *jit, uint8_t reg1, uint8_t reg2);
static void __attribute__((unused)) emit_je_rel32(x86_64_jit_t *jit, int32_t offset);
static void __attribute__((unused)) emit_jne_rel32(x86_64_jit_t *jit, int32_t offset);
static void __attribute__((unused)) emit_jg_rel32(x86_64_jit_t *jit, int32_t offset);
static void __attribute__((unused)) emit_jl_rel32(x86_64_jit_t *jit, int32_t offset);
static void __attribute__((unused)) emit_jmp_rel32(x86_64_jit_t *jit, int32_t offset);
static void emit_push_reg(x86_64_jit_t *jit, uint8_t reg);
static void emit_pop_reg(x86_64_jit_t *jit, uint8_t reg);
static void emit_ret(x86_64_jit_t *jit);

// Function prologue and epilogue
static void emit_prologue(x86_64_jit_t *jit);
static void emit_epilogue(x86_64_jit_t *jit);

// CPU capability detection for Phase 2.2 AVX2 optimizations
static void detect_cpu_capabilities(x86_64_caps_t *caps);

// AVX2 instruction generation for Phase 2.2
static void emit_vmovdqu_ymm_mem(x86_64_jit_t *jit, uint8_t ymm, uint8_t base, int32_t offset);
static void emit_vmovdqu_mem_ymm(x86_64_jit_t *jit, uint8_t base, int32_t offset, uint8_t ymm);
static void emit_vpcmpeqb_ymm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2);
static void emit_vpmovmskb_reg_ymm(x86_64_jit_t *jit, uint8_t reg, uint8_t ymm);
static void emit_vpxor_ymm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2);
static void emit_vpand_ymm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2);
static void emit_vpor_ymm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2);
static void emit_vzeroupper(x86_64_jit_t *jit);

// Optimized IPv6 hash function using AVX2
static void emit_avx2_ipv6_hash(x86_64_jit_t *jit);

// Parallel processing for multiple packets
static void emit_avx2_parallel_128bit_cmp(x86_64_jit_t *jit);

// Basic instruction emission
static void emit_byte(x86_64_jit_t *jit, uint8_t byte) {
    if (jit->code_pos >= jit->code_size) {
        return; // Buffer overflow protection
    }
    jit->code[jit->code_pos++] = byte;
}

static void __attribute__((unused)) emit_word(x86_64_jit_t *jit, uint16_t word) {
    emit_byte(jit, word & 0xFF);
    emit_byte(jit, (word >> 8) & 0xFF);
}

static void emit_dword(x86_64_jit_t *jit, uint32_t dword) {
    emit_byte(jit, dword & 0xFF);
    emit_byte(jit, (dword >> 8) & 0xFF);
    emit_byte(jit, (dword >> 16) & 0xFF);
    emit_byte(jit, (dword >> 24) & 0xFF);
}

static void emit_qword(x86_64_jit_t *jit, uint64_t qword) {
    emit_dword(jit, qword & 0xFFFFFFFF);
    emit_dword(jit, (qword >> 32) & 0xFFFFFFFF);
}

// Sentinel returned by alloc_reg when the register-based operand stack has no
// free physical register left. Callers MUST treat this as "cannot compile" and
// decline (return NULL) so execution falls back to the bounds-checked
// interpreter -- never emit code that aliases two live stack slots onto the
// same register, which silently corrupts results.
#define REG_NONE 0xFF

// Register allocation for the register-modelled operand stack.
//
// The operand stack is modelled in the eight registers R8-R15. Each live stack
// slot occupies exactly one of them; a value "carries" its register as it moves
// (SWAP swaps the names, arithmetic consumes the top). The previous allocator
// used a monotonically increasing counter that (a) never recycled a register
// after a POP and (b) silently aliased every allocation past the eighth onto R8
// -- so any program with more than eight cumulative pushes produced wrong
// results. This allocator instead derives liveness from the current stack
// contents: it returns the lowest-numbered register not already holding a live
// stack slot, or REG_NONE when all eight are in use (depth would exceed 8).
static uint8_t alloc_reg(x86_64_jit_t *jit) {
    static const uint8_t available_regs[] = {R8, R9, R10, R11, R12, R13, R14, R15};

    for (uint32_t i = 0; i < sizeof(available_regs) / sizeof(available_regs[0]); i++) {
        uint8_t candidate = available_regs[i];
        bool in_use = false;
        for (uint32_t j = 0; j < jit->stack_depth; j++) {
            if (jit->stack_regs[j] == candidate) { in_use = true; break; }
        }
        if (!in_use) {
            return candidate;
        }
    }
    return REG_NONE;  // operand stack deeper than the 8 available registers
}

static void free_reg(x86_64_jit_t *jit, uint8_t reg) {
    (void)jit;
    (void)reg;
    // Simple allocator - could be improved
}

// REX prefix generation
static uint8_t rex_prefix(uint8_t w, uint8_t r, uint8_t x, uint8_t b) {
    return 0x40 | (w << 3) | (r << 2) | (x << 1) | b;
}

// ModR/M byte generation
static uint8_t modrm_byte(uint8_t mod, uint8_t reg, uint8_t rm) {
    return (mod << 6) | (reg << 3) | rm;
}

// Move immediate 64-bit value to register
static void emit_mov_reg_imm64(x86_64_jit_t *jit, uint8_t reg, uint64_t imm) {
    // REX.W + B (if reg >= 8)
    emit_byte(jit, rex_prefix(1, 0, 0, reg >= 8 ? 1 : 0));
    // MOV r64, imm64 (0xB8 + reg)
    emit_byte(jit, 0xB8 + (reg & 7));
    emit_qword(jit, imm);
}

// Move register to register
static void emit_mov_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src) {
    // REX.W + R + B
    emit_byte(jit, rex_prefix(1, src >= 8 ? 1 : 0, 0, dst >= 8 ? 1 : 0));
    // MOV r64, r/m64
    emit_byte(jit, 0x89);
    emit_byte(jit, modrm_byte(3, src & 7, dst & 7));
}

// Load from memory [base + offset] to register
static void emit_mov_reg_mem(x86_64_jit_t *jit, uint8_t reg, uint8_t base, int32_t offset) {
    // REX.W + R + B
    emit_byte(jit, rex_prefix(1, reg >= 8 ? 1 : 0, 0, base >= 8 ? 1 : 0));
    // MOV r64, r/m64
    emit_byte(jit, 0x8B);
    
    if (offset == 0 && (base & 7) != 5) {
        // [base]
        emit_byte(jit, modrm_byte(0, reg & 7, base & 7));
    } else if (offset >= -128 && offset <= 127) {
        // [base + disp8]
        emit_byte(jit, modrm_byte(1, reg & 7, base & 7));
        emit_byte(jit, offset & 0xFF);
    } else {
        // [base + disp32]
        emit_byte(jit, modrm_byte(2, reg & 7, base & 7));
        emit_dword(jit, offset);
    }
}

// Store register to memory [base + offset]
static void emit_mov_mem_reg(x86_64_jit_t *jit, uint8_t base, int32_t offset, uint8_t reg) {
    // REX.W + R + B
    emit_byte(jit, rex_prefix(1, reg >= 8 ? 1 : 0, 0, base >= 8 ? 1 : 0));
    // MOV r/m64, r64
    emit_byte(jit, 0x89);
    
    if (offset == 0 && (base & 7) != 5) {
        emit_byte(jit, modrm_byte(0, reg & 7, base & 7));
    } else if (offset >= -128 && offset <= 127) {
        emit_byte(jit, modrm_byte(1, reg & 7, base & 7));
        emit_byte(jit, offset & 0xFF);
    } else {
        emit_byte(jit, modrm_byte(2, reg & 7, base & 7));
        emit_dword(jit, offset);
    }
}

// Arithmetic operations
static void emit_add_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src) {
    emit_byte(jit, rex_prefix(1, src >= 8 ? 1 : 0, 0, dst >= 8 ? 1 : 0));
    emit_byte(jit, 0x01);  // ADD r/m64, r64
    emit_byte(jit, modrm_byte(3, src & 7, dst & 7));
}

static void emit_sub_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src) {
    emit_byte(jit, rex_prefix(1, src >= 8 ? 1 : 0, 0, dst >= 8 ? 1 : 0));
    emit_byte(jit, 0x29);  // SUB r/m64, r64
    emit_byte(jit, modrm_byte(3, src & 7, dst & 7));
}

static void emit_mul_reg(x86_64_jit_t *jit, uint8_t reg) {
    emit_byte(jit, rex_prefix(1, 0, 0, reg >= 8 ? 1 : 0));
    emit_byte(jit, 0xF7);  // MUL r/m64
    emit_byte(jit, modrm_byte(3, 4, reg & 7));
}

static void emit_div_reg(x86_64_jit_t *jit, uint8_t reg) {
    emit_byte(jit, rex_prefix(1, 0, 0, reg >= 8 ? 1 : 0));
    emit_byte(jit, 0xF7);  // DIV r/m64
    emit_byte(jit, modrm_byte(3, 6, reg & 7));
}

static void emit_and_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src) {
    emit_byte(jit, rex_prefix(1, src >= 8 ? 1 : 0, 0, dst >= 8 ? 1 : 0));
    emit_byte(jit, 0x21);  // AND r/m64, r64
    emit_byte(jit, modrm_byte(3, src & 7, dst & 7));
}

static void emit_or_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src) {
    emit_byte(jit, rex_prefix(1, src >= 8 ? 1 : 0, 0, dst >= 8 ? 1 : 0));
    emit_byte(jit, 0x09);  // OR r/m64, r64
    emit_byte(jit, modrm_byte(3, src & 7, dst & 7));
}

static void emit_xor_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src) {
    emit_byte(jit, rex_prefix(1, src >= 8 ? 1 : 0, 0, dst >= 8 ? 1 : 0));
    emit_byte(jit, 0x31);  // XOR r/m64, r64
    emit_byte(jit, modrm_byte(3, src & 7, dst & 7));
}

static void emit_shl_reg_cl(x86_64_jit_t *jit, uint8_t reg) {
    emit_byte(jit, rex_prefix(1, 0, 0, reg >= 8 ? 1 : 0));
    emit_byte(jit, 0xD3);  // SHL r/m64, CL
    emit_byte(jit, modrm_byte(3, 4, reg & 7));
}

static void emit_shr_reg_cl(x86_64_jit_t *jit, uint8_t reg) {
    emit_byte(jit, rex_prefix(1, 0, 0, reg >= 8 ? 1 : 0));
    emit_byte(jit, 0xD3);  // SHR r/m64, CL
    emit_byte(jit, modrm_byte(3, 5, reg & 7));
}

static void emit_not_reg(x86_64_jit_t *jit, uint8_t reg) {
    emit_byte(jit, rex_prefix(1, 0, 0, reg >= 8 ? 1 : 0));
    emit_byte(jit, 0xF7);  // NOT r/m64
    emit_byte(jit, modrm_byte(3, 2, reg & 7));
}

static void emit_neg_reg(x86_64_jit_t *jit, uint8_t reg) {
    emit_byte(jit, rex_prefix(1, 0, 0, reg >= 8 ? 1 : 0));
    emit_byte(jit, 0xF7);  // NEG r/m64
    emit_byte(jit, modrm_byte(3, 3, reg & 7));
}

// Comparison and jumps
static void emit_cmp_reg_reg(x86_64_jit_t *jit, uint8_t reg1, uint8_t reg2) {
    emit_byte(jit, rex_prefix(1, reg2 >= 8 ? 1 : 0, 0, reg1 >= 8 ? 1 : 0));
    emit_byte(jit, 0x39);  // CMP r/m64, r64
    emit_byte(jit, modrm_byte(3, reg2 & 7, reg1 & 7));
}

static void emit_je_rel32(x86_64_jit_t *jit, int32_t offset) {
    emit_byte(jit, 0x0F);  // Two-byte opcode prefix
    emit_byte(jit, 0x84);  // JE rel32
    emit_dword(jit, offset);
}

static void emit_jne_rel32(x86_64_jit_t *jit, int32_t offset) {
    emit_byte(jit, 0x0F);
    emit_byte(jit, 0x85);  // JNE rel32
    emit_dword(jit, offset);
}

static void emit_jg_rel32(x86_64_jit_t *jit, int32_t offset) {
    emit_byte(jit, 0x0F);
    emit_byte(jit, 0x8F);  // JG rel32
    emit_dword(jit, offset);
}

static void emit_jl_rel32(x86_64_jit_t *jit, int32_t offset) {
    emit_byte(jit, 0x0F);
    emit_byte(jit, 0x8C);  // JL rel32
    emit_dword(jit, offset);
}

static void emit_jmp_rel32(x86_64_jit_t *jit, int32_t offset) {
    emit_byte(jit, 0xE9);  // JMP rel32
    emit_dword(jit, offset);
}

// Additional x86_64 instructions for Phase 2.2 AVX2 optimizations
static void emit_cmp_reg_imm32(x86_64_jit_t *jit, uint8_t reg, uint32_t imm) {
    if (reg >= 8) {
        emit_byte(jit, rex_prefix(1, 0, 0, 1));
    } else {
        emit_byte(jit, rex_prefix(1, 0, 0, 0));
    }
    emit_byte(jit, 0x81);  // CMP r/m64, imm32
    emit_byte(jit, modrm_byte(3, 7, reg & 7));  // /7 for CMP
    emit_dword(jit, imm);
}

static void emit_sete_reg8(x86_64_jit_t *jit, uint8_t reg) {
    if (reg >= 8) {
        emit_byte(jit, rex_prefix(0, 0, 0, 1));
    }
    emit_byte(jit, 0x0F);  // Two-byte opcode prefix
    emit_byte(jit, 0x94);  // SETE r/m8
    emit_byte(jit, modrm_byte(3, 0, reg & 7));
}

// Stack operations
static void emit_push_reg(x86_64_jit_t *jit, uint8_t reg) {
    if (reg >= 8) {
        emit_byte(jit, rex_prefix(0, 0, 0, 1));
    }
    emit_byte(jit, 0x50 + (reg & 7));  // PUSH r64
}

static void emit_pop_reg(x86_64_jit_t *jit, uint8_t reg) {
    if (reg >= 8) {
        emit_byte(jit, rex_prefix(0, 0, 0, 1));
    }
    emit_byte(jit, 0x58 + (reg & 7));  // POP r64
}

static void emit_ret(x86_64_jit_t *jit) {
    emit_byte(jit, 0xC3);  // RET
}

// Function prologue: set up the stack frame and preserve callee-saved state.
//
// The operand stack is modelled in R8-R15 (see alloc_reg). Of those, R12-R15
// are callee-saved under the x86-64 System V ABI, so they MUST be preserved
// across the call or we corrupt the caller's registers. The previous prologue
// saved only RBP and clobbered R12-R15 for any program deep enough to allocate
// them -- an ABI violation. We now push R12-R15 and restore them in the
// epilogue. (We do not use RBX, so it is left untouched.) R8-R11 are
// caller-saved and need no preservation.
static void emit_prologue(x86_64_jit_t *jit) {
    // push rbp ; mov rbp, rsp
    emit_push_reg(jit, RBP);
    emit_mov_reg_reg(jit, RBP, RSP);
    // Preserve callee-saved registers used as operand-stack slots.
    emit_push_reg(jit, R12);
    emit_push_reg(jit, R13);
    emit_push_reg(jit, R14);
    emit_push_reg(jit, R15);
}

// Function epilogue: restore callee-saved state and return.
static void emit_epilogue(x86_64_jit_t *jit) {
    // Ensure AVX state is properly cleaned up
    if (jit->use_avx2) {
        emit_vzeroupper(jit);
    }

    // Restore callee-saved registers (reverse push order), then rbp, then ret.
    emit_pop_reg(jit, R15);
    emit_pop_reg(jit, R14);
    emit_pop_reg(jit, R13);
    emit_pop_reg(jit, R12);
    emit_pop_reg(jit, RBP);
    emit_ret(jit);
}

// Missing emit functions - add stubs for Linux compatibility
static void emit_sete_reg(x86_64_jit_t *jit, uint8_t reg) {
    // Wrapper for emit_sete_reg8 for compatibility
    emit_sete_reg8(jit, reg);
}

// XMM instruction stubs for Linux compatibility
static void emit_vmovdqu_xmm_mem(x86_64_jit_t *jit, uint8_t dst, uint8_t base, int32_t offset) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)dst; (void)base; (void)offset;
    #else
        (void)jit; (void)dst; (void)base; (void)offset;
    #endif
}

static void emit_vpcmpeqb_xmm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)dst; (void)src1; (void)src2;
    #else
        (void)jit; (void)dst; (void)src1; (void)src2;
    #endif
}

static void emit_vpcmpeqd_ymm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)dst; (void)src1; (void)src2;
    #else
        (void)jit; (void)dst; (void)src1; (void)src2;
    #endif
}

static void emit_vpmovmskb_reg_xmm(x86_64_jit_t *jit, uint8_t reg, uint8_t xmm) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)reg; (void)xmm;
    #else
        (void)jit; (void)reg; (void)xmm;
    #endif
}

static void emit_movdqu_xmm_mem(x86_64_jit_t *jit, uint8_t dst, uint8_t base, int32_t offset) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)dst; (void)base; (void)offset;
    #else
        (void)jit; (void)dst; (void)base; (void)offset;
    #endif
}

static void emit_pcmpeqb_xmm(x86_64_jit_t *jit, uint8_t dst, uint8_t src) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)dst; (void)src;
    #else
        (void)jit; (void)dst; (void)src;
    #endif
}

static void emit_pmovmskb_reg_xmm(x86_64_jit_t *jit, uint8_t reg, uint8_t xmm) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)reg; (void)xmm;
    #else
        (void)jit; (void)reg; (void)xmm;
    #endif
}

// Memory and arithmetic instruction stubs
static void emit_prefetcht0_mem(x86_64_jit_t *jit, uint8_t base, int32_t offset) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)base; (void)offset;
    #else
        (void)jit; (void)base; (void)offset;
    #endif
}

static void emit_mov_mem32_reg(x86_64_jit_t *jit, uint8_t base, int32_t offset, uint8_t reg) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)base; (void)offset; (void)reg;
    #else
        (void)jit; (void)base; (void)offset; (void)reg;
    #endif
}

static void emit_add_reg_imm(x86_64_jit_t *jit, uint8_t reg, int32_t imm) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)reg; (void)imm;
    #else
        (void)jit; (void)reg; (void)imm;
    #endif
}

static void emit_andn_reg_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)dst; (void)src1; (void)src2;
    #else
        (void)jit; (void)dst; (void)src1; (void)src2;
    #endif
}

static void emit_and_reg_mem32(x86_64_jit_t *jit, uint8_t reg, uint8_t base, int32_t offset) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)reg; (void)base; (void)offset;
    #else
        (void)jit; (void)reg; (void)base; (void)offset;
    #endif
}

static void emit_nop(x86_64_jit_t *jit) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit;
    #else
        (void)jit;
    #endif
}

static void emit_mov_reg_mem32(x86_64_jit_t *jit, uint8_t dst, uint8_t base, int32_t offset) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)dst; (void)base; (void)offset;
    #else
        (void)jit; (void)dst; (void)base; (void)offset;
    #endif
}

static void emit_cmp_reg_mem32(x86_64_jit_t *jit, uint8_t reg, uint8_t base, int32_t offset) {
    #ifdef VFM_PLATFORM_LINUX
        (void)jit; (void)reg; (void)base; (void)offset;
    #else
        (void)jit; (void)reg; (void)base; (void)offset;
    #endif
}

// CPU capability detection for Phase 2.2 AVX2 optimizations
static void detect_cpu_capabilities(x86_64_caps_t *caps) {
    // Early return on Linux due to incomplete implementation
    #ifdef VFM_PLATFORM_LINUX
        if (caps) {
            caps->has_avx2 = false;
            caps->has_bmi2 = false;
            caps->has_popcnt = false;
        }
        return;
    #endif
    memset(caps, 0, sizeof(*caps));
    
#ifdef __x86_64__
    uint32_t eax, ebx, ecx, edx;
    
    // Check CPUID support
    if (__get_cpuid_max(0, NULL) < 1) {
        return;
    }
    
    // Detect CPU vendor for Intel/AMD specific instruction preferences
    if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        if (ebx == 0x756e6547 && edx == 0x49656e69 && ecx == 0x6c65746e) {
            caps->vendor = CPU_VENDOR_INTEL;  // "GenuineIntel"
        } else if (ebx == 0x68747541 && edx == 0x69746e65 && ecx == 0x444d4163) {
            caps->vendor = CPU_VENDOR_AMD;    // "AuthenticAMD"
        } else {
            caps->vendor = CPU_VENDOR_UNKNOWN;
        }
    }
    
    // Get feature flags
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        caps->has_popcnt = (ecx & bit_POPCNT) != 0;
        caps->has_prefetch = true; // PREFETCH available on all modern x86_64
    }
    
    // Check extended features
    if (__get_cpuid_max(0, NULL) >= 7) {
        if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
            caps->has_avx2 = (ebx & bit_AVX2) != 0;
            caps->has_bmi1 = (ebx & bit_BMI) != 0;
            caps->has_bmi2 = (ebx & bit_BMI2) != 0;
            caps->has_lzcnt = (ebx & bit_LZCNT) != 0;
        }
    }
#endif
}

// VEX prefix encoding for AVX2 instructions
static void emit_vex3(x86_64_jit_t *jit, uint8_t rxb, uint8_t map_select, 
                      uint8_t w_vvvv_l_pp) {
    (void)map_select; // Currently unused but kept for future extension
    emit_byte(jit, 0xC4);  // 3-byte VEX prefix
    emit_byte(jit, rxb);   // RXB and map_select
    emit_byte(jit, w_vvvv_l_pp);
}

// VZEROUPPER - transition between AVX and SSE
static void emit_vzeroupper(x86_64_jit_t *jit) {
    emit_byte(jit, 0xC5);  // 2-byte VEX prefix
    emit_byte(jit, 0xF8);  // vzeroupper encoding
    emit_byte(jit, 0x77);
}

// VMOVDQU YMM, [mem] - unaligned 256-bit load
static void emit_vmovdqu_ymm_mem(x86_64_jit_t *jit, uint8_t ymm, uint8_t base, int32_t offset) {
    // VEX.256.F3.0F.WIG 6F /r
    uint8_t rxb = 0xE0 | (1 << 2);  // RXB bits + map_select (0F)
    uint8_t w_vvvv_l_pp = 0x44;     // W=0, vvvv=1111, L=1 (256-bit), pp=01 (F3)
    
    emit_vex3(jit, rxb, 0x01, w_vvvv_l_pp);
    emit_byte(jit, 0x6F);  // VMOVDQU opcode
    
    // ModR/M and displacement
    if (offset == 0 && (base & 7) != 5) {
        emit_byte(jit, modrm_byte(0, ymm & 7, base & 7));
    } else if (offset >= -128 && offset <= 127) {
        emit_byte(jit, modrm_byte(1, ymm & 7, base & 7));
        emit_byte(jit, offset & 0xFF);
    } else {
        emit_byte(jit, modrm_byte(2, ymm & 7, base & 7));
        emit_dword(jit, offset);
    }
}

// VMOVDQU [mem], YMM - unaligned 256-bit store
static void __attribute__((unused)) emit_vmovdqu_mem_ymm(x86_64_jit_t *jit, uint8_t base, int32_t offset, uint8_t ymm) {
    // VEX.256.F3.0F.WIG 7F /r
    uint8_t rxb = 0xE0 | (1 << 2);  // RXB bits + map_select (0F)
    uint8_t w_vvvv_l_pp = 0x44;     // W=0, vvvv=1111, L=1 (256-bit), pp=01 (F3)
    
    emit_vex3(jit, rxb, 0x01, w_vvvv_l_pp);
    emit_byte(jit, 0x7F);  // VMOVDQU opcode
    
    // ModR/M and displacement
    if (offset == 0 && (base & 7) != 5) {
        emit_byte(jit, modrm_byte(0, ymm & 7, base & 7));
    } else if (offset >= -128 && offset <= 127) {
        emit_byte(jit, modrm_byte(1, ymm & 7, base & 7));
        emit_byte(jit, offset & 0xFF);
    } else {
        emit_byte(jit, modrm_byte(2, ymm & 7, base & 7));
        emit_dword(jit, offset);
    }
}

// VPCMPEQB YMM, YMM, YMM - compare packed bytes for equality
static void emit_vpcmpeqb_ymm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2) {
    // VEX.NDS.256.66.0F.WIG 74 /r
    uint8_t rxb = 0xE0 | (1 << 2);  // RXB bits + map_select (0F)
    uint8_t w_vvvv_l_pp = 0x40 | ((~src1 & 0xF) << 3) | 0x01;  // W=0, vvvv=~src1, L=1, pp=01 (66)
    
    emit_vex3(jit, rxb, 0x01, w_vvvv_l_pp);
    emit_byte(jit, 0x74);  // VPCMPEQB opcode
    emit_byte(jit, modrm_byte(3, dst & 7, src2 & 7));
}

// VPMOVMSKB reg, YMM - extract byte mask from YMM register
static void emit_vpmovmskb_reg_ymm(x86_64_jit_t *jit, uint8_t reg, uint8_t ymm) {
    // VEX.256.66.0F.WIG D7 /r
    uint8_t rxb = 0xE0 | (1 << 2);  // RXB bits + map_select (0F)
    uint8_t w_vvvv_l_pp = 0x44 | 0x01;  // W=0, vvvv=1111, L=1, pp=01 (66)
    
    emit_vex3(jit, rxb, 0x01, w_vvvv_l_pp);
    emit_byte(jit, 0xD7);  // VPMOVMSKB opcode
    emit_byte(jit, modrm_byte(3, reg & 7, ymm & 7));
}

// VPXOR YMM, YMM, YMM - bitwise XOR
static void emit_vpxor_ymm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2) {
    // VEX.NDS.256.66.0F.WIG EF /r
    uint8_t rxb = 0xE0 | (1 << 2);  // RXB bits + map_select (0F)
    uint8_t w_vvvv_l_pp = 0x40 | ((~src1 & 0xF) << 3) | 0x01;  // W=0, vvvv=~src1, L=1, pp=01 (66)
    
    emit_vex3(jit, rxb, 0x01, w_vvvv_l_pp);
    emit_byte(jit, 0xEF);  // VPXOR opcode
    emit_byte(jit, modrm_byte(3, dst & 7, src2 & 7));
}

// VPAND YMM, YMM, YMM - bitwise AND
static void __attribute__((unused)) emit_vpand_ymm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2) {
    // VEX.NDS.256.66.0F.WIG DB /r
    uint8_t rxb = 0xE0 | (1 << 2);  // RXB bits + map_select (0F)
    uint8_t w_vvvv_l_pp = 0x40 | ((~src1 & 0xF) << 3) | 0x01;  // W=0, vvvv=~src1, L=1, pp=01 (66)
    
    emit_vex3(jit, rxb, 0x01, w_vvvv_l_pp);
    emit_byte(jit, 0xDB);  // VPAND opcode
    emit_byte(jit, modrm_byte(3, dst & 7, src2 & 7));
}

// VPOR YMM, YMM, YMM - bitwise OR
static void __attribute__((unused)) emit_vpor_ymm(x86_64_jit_t *jit, uint8_t dst, uint8_t src1, uint8_t src2) {
    // VEX.NDS.256.66.0F.WIG EB /r
    uint8_t rxb = 0xE0 | (1 << 2);  // RXB bits + map_select (0F)
    uint8_t w_vvvv_l_pp = 0x40 | ((~src1 & 0xF) << 3) | 0x01;  // W=0, vvvv=~src1, L=1, pp=01 (66)
    
    emit_vex3(jit, rxb, 0x01, w_vvvv_l_pp);
    emit_byte(jit, 0xEB);  // VPOR opcode
    emit_byte(jit, modrm_byte(3, dst & 7, src2 & 7));
}

// Optimized IPv6 hash function using AVX2 (Phase 2.2)
static void __attribute__((unused)) emit_avx2_ipv6_hash(x86_64_jit_t *jit) {
    // Load IPv6 address (128 bits) into YMM0 (lower 128 bits)
    // ymm0 = IPv6 source address (16 bytes)
    emit_vmovdqu_ymm_mem(jit, YMM0, RDI, 24);  // IPv6 src offset in packet
    
    // Load IPv6 destination address into YMM1
    // ymm1 = IPv6 destination address (16 bytes)  
    emit_vmovdqu_ymm_mem(jit, YMM1, RDI, 40);  // IPv6 dst offset in packet
    
    // XOR source and destination for hash mixing
    emit_vpxor_ymm(jit, YMM2, YMM0, YMM1);     // ymm2 = src XOR dst
    
    // Additional hash mixing with rotated values
    // This would need custom rotation, simplified here
    emit_vpxor_ymm(jit, YMM3, YMM2, YMM0);     // ymm3 = mixed hash
    
    // Extract hash to general purpose register
    // Convert to 32-bit hash by combining parts
    emit_vpmovmskb_reg_ymm(jit, RAX, YMM3);    // Extract byte mask as hash
}

// Parallel processing for multiple 128-bit comparisons (Phase 2.2)
static void __attribute__((unused)) emit_avx2_parallel_128bit_cmp(x86_64_jit_t *jit) {
    // Load two 128-bit values into single YMM register (256 bits total)
    // This allows comparing 2 pairs simultaneously
    
    // Load first pair: value1_low, value1_high, value2_low, value2_high
    emit_vmovdqu_ymm_mem(jit, YMM0, RDI, 0);   // Load first 256-bit chunk
    emit_vmovdqu_ymm_mem(jit, YMM1, RDI, 32);  // Load second 256-bit chunk
    
    // Compare for equality
    emit_vpcmpeqb_ymm(jit, YMM2, YMM0, YMM1);  // Byte-wise comparison
    
    // Extract comparison result
    emit_vpmovmskb_reg_ymm(jit, RAX, YMM2);    // Get comparison mask
    
    // Check if all bytes matched (mask should be 0xFFFFFFFF for full match)
    emit_mov_reg_imm64(jit, RCX, 0xFFFFFFFF);
    emit_cmp_reg_reg(jit, RAX, RCX);
}

// Emit a packet-bounds check for a load of `sz` bytes at packet offset `off`.
// Mirrors the interpreter's BOUNDS_CHECK: if packet_len < off+sz the load would
// read past the packet, so branch to the shared failure handler at
// `fail_target` (which returns VFM_ERROR_BOUNDS). The uint16 packet_len
// argument is passed zero-extended in ESI, so a 32-bit compare is exact and
// does not depend on the undefined high 48 bits of RSI.
static void emit_load_bounds_check(x86_64_jit_t *jit, uint32_t fail_target,
                                   uint32_t off, uint32_t sz) {
    // cmp esi, off+sz
    emit_byte(jit, 0x81);
    emit_byte(jit, modrm_byte(3, 7, RSI));  // /7 = CMP, rm = RSI
    emit_dword(jit, off + sz);
    // jb fail  (unsigned: packet_len < off+sz => out of bounds)
    emit_byte(jit, 0x0F);
    emit_byte(jit, 0x82);
    int32_t rel = (int32_t)(fail_target - (jit->code_pos + 4));
    emit_dword(jit, (uint32_t)rel);
}

// Main JIT compilation function
void* vfm_jit_compile_x86_64(const uint8_t *program, uint32_t len) {
    if (!program || len == 0) {
        return NULL;
    }
    
    // Allocate executable memory
    size_t code_size = len * 32;  // Conservative estimate
    uint8_t *code = mmap(NULL, code_size, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        return NULL;
    }
    
    x86_64_jit_t jit = {
        .code = code,
        .code_size = code_size,
        .code_pos = 0,
        .stack_depth = 0,
        .next_reg = 0,
        .labels = calloc(len, sizeof(uint32_t)),
        .label_count = 0,
        .use_avx2 = false
    };
    
    // Detect CPU capabilities for Phase 2.2 AVX2 optimizations
    detect_cpu_capabilities(&jit.caps);
    jit.use_avx2 = jit.caps.has_avx2;
    
    if (!jit.labels) {
        munmap(code, code_size);
        return NULL;
    }
    
    // Emit function prologue
    emit_prologue(&jit);

    // Emit the shared bounds-failure handler once, up front, and jump over it
    // on the normal path. Loads branch here when an offset would read past the
    // packet; it returns VFM_ERROR_BOUNDS (-1), exactly what the interpreter
    // returns for an out-of-bounds load, so the JIT and oracle agree even on
    // malformed offsets.
    emit_byte(&jit, 0xE9);                   // JMP rel32 over the handler
    uint32_t jmp_patch = jit.code_pos;
    emit_dword(&jit, 0);                     // placeholder displacement
    uint32_t fail_target = jit.code_pos;     // handler entry
    emit_mov_reg_imm64(&jit, RAX, (uint64_t)(int64_t)VFM_ERROR_BOUNDS);
    emit_epilogue(&jit);
    {
        int32_t over_rel = (int32_t)(jit.code_pos - (jmp_patch + 4));
        jit.code[jmp_patch + 0] = (uint8_t)(over_rel & 0xFF);
        jit.code[jmp_patch + 1] = (uint8_t)((over_rel >> 8) & 0xFF);
        jit.code[jmp_patch + 2] = (uint8_t)((over_rel >> 16) & 0xFF);
        jit.code[jmp_patch + 3] = (uint8_t)((over_rel >> 24) & 0xFF);
    }

    // Compile VFM instructions
    uint32_t pc = 0;
    while (pc < len) {
        // Safety: the operand stack is tracked in a fixed-size register map
        // (jit.stack_regs). The widest instruction (PUSH128/LD128) pushes two
        // slots, so require two slots of headroom before compiling any
        // instruction. If the program's stack depth would exceed what the JIT
        // can represent, abort compilation and fall back to the safe
        // interpreter instead of writing past stack_regs[] -- an overflow that
        // corrupts the adjacent struct fields (next_reg, labels) and crashes
        // in free(jit.labels). The interpreter still enforces the real
        // VFM_ERROR_STACK_OVERFLOW limit at runtime.
        if (jit.stack_depth + 2 > sizeof(jit.stack_regs) / sizeof(jit.stack_regs[0])) {
            goto decline;
        }
        uint8_t opcode = program[pc++];
        
        switch (opcode) {
            case VFM_LD8: {
                uint16_t offset = *(uint16_t*)&program[pc];
                pc += 2;

                uint8_t reg = alloc_reg(&jit);
                if (reg == REG_NONE) goto decline;

                // Interpreter op_ld8: BOUNDS_CHECK(offset, 1); push packet[offset]
                // as a zero-extended byte. Previously this emitted MOV r8, [rdi+off]
                // (opcode 0x8A writes ONLY bits 0-7) followed by a 64-bit reg->reg
                // self-move, leaving bits 8-63 holding register-allocator garbage
                // -- so any later use of the value (compare, arith) diverged from
                // the interpreter. Use MOVZX r32, byte [rdi+off] (0F B6), which
                // zero-extends the loaded byte across the full 64-bit register
                // (a 32-bit destination write clears bits 32-63).
                emit_load_bounds_check(&jit, fail_target, offset, 1);
                emit_byte(&jit, rex_prefix(0, reg >= 8 ? 1 : 0, 0, 0));
                emit_byte(&jit, 0x0F);
                emit_byte(&jit, 0xB6);  // MOVZX r32, r/m8
                emit_byte(&jit, modrm_byte(2, reg & 7, RDI));
                emit_dword(&jit, offset);

                jit.stack_regs[jit.stack_depth++] = reg;
                break;
            }

            case VFM_LD16: {
                uint16_t offset = *(uint16_t*)&program[pc];
                pc += 2;

                uint8_t reg = alloc_reg(&jit);
                if (reg == REG_NONE) goto decline;

                // Interpreter op_ld16: BOUNDS_CHECK(offset, 2); push
                // ntohs(*(uint16*)(packet+offset)) zero-extended. Previously this
                // used a 16-bit MOV (0x66 0x8B) that writes only bits 0-15 (bits
                // 16-63 kept garbage) and then BSWAP r16, whose result is
                // architecturally undefined for a 16-bit operand. Use MOVZX r32,
                // word [rdi+off] (0F B7) to load and zero-extend, then ROR r16, 8
                // to byte-swap the two bytes (ntohs on a little-endian host). ROR
                // on the 16-bit operand leaves the already-zero bits 16-63 intact.
                emit_load_bounds_check(&jit, fail_target, offset, 2);
                emit_byte(&jit, rex_prefix(0, reg >= 8 ? 1 : 0, 0, 0));
                emit_byte(&jit, 0x0F);
                emit_byte(&jit, 0xB7);  // MOVZX r32, r/m16
                emit_byte(&jit, modrm_byte(2, reg & 7, RDI));
                emit_dword(&jit, offset);

                // ror reg16, 8  (swap the two bytes => network-to-host order)
                emit_byte(&jit, 0x66);                               // 16-bit operand
                if (reg >= 8) emit_byte(&jit, rex_prefix(0, 0, 0, 1)); // REX.B
                emit_byte(&jit, 0xC1);                               // ROR r/m16, imm8
                emit_byte(&jit, modrm_byte(3, 1, reg & 7));          // /1 = ROR
                emit_byte(&jit, 8);

                jit.stack_regs[jit.stack_depth++] = reg;
                break;
            }

            case VFM_LD32: {
                uint16_t offset = *(uint16_t*)&program[pc];
                pc += 2;

                uint8_t reg = alloc_reg(&jit);
                if (reg == REG_NONE) goto decline;

                // Interpreter op_ld32: BOUNDS_CHECK(offset, 4); push
                // ntohl(*(uint32*)(packet+offset)) zero-extended. A 32-bit MOV
                // into the register's low half auto-zero-extends bits 32-63, and
                // BSWAP on the 32-bit operand converts network to host order and
                // likewise leaves bits 32-63 clear -- so this load was already
                // correct; we only add the missing bounds check.
                emit_load_bounds_check(&jit, fail_target, offset, 4);
                emit_byte(&jit, rex_prefix(0, reg >= 8 ? 1 : 0, 0, 0));
                emit_byte(&jit, 0x8B);  // MOV r32, r/m32
                emit_byte(&jit, modrm_byte(2, reg & 7, RDI));
                emit_dword(&jit, offset);

                // Convert network to host order
                if (reg >= 8) emit_byte(&jit, rex_prefix(0, 0, 0, 1));
                emit_byte(&jit, 0x0F);
                emit_byte(&jit, 0xC8 + (reg & 7));  // BSWAP r32

                jit.stack_regs[jit.stack_depth++] = reg;
                break;
            }

            case VFM_PUSH: {
                uint64_t value = *(uint64_t*)&program[pc];
                pc += 8;

                uint8_t reg = alloc_reg(&jit);
                if (reg == REG_NONE) goto decline;
                emit_mov_reg_imm64(&jit, reg, value);
                jit.stack_regs[jit.stack_depth++] = reg;
                break;
            }
            
            case VFM_POP: {
                if (jit.stack_depth > 0) {
                    uint8_t reg = jit.stack_regs[--jit.stack_depth];
                    free_reg(&jit, reg);
                }
                break;
            }
            
            case VFM_DUP: {
                if (jit.stack_depth > 0) {
                    uint8_t src_reg = jit.stack_regs[jit.stack_depth - 1];
                    uint8_t dst_reg = alloc_reg(&jit);
                    if (dst_reg == REG_NONE) goto decline;
                    emit_mov_reg_reg(&jit, dst_reg, src_reg);
                    jit.stack_regs[jit.stack_depth++] = dst_reg;
                }
                break;
            }
            
            case VFM_SWAP: {
                if (jit.stack_depth >= 2) {
                    uint8_t reg1 = jit.stack_regs[jit.stack_depth - 1];
                    uint8_t reg2 = jit.stack_regs[jit.stack_depth - 2];
                    jit.stack_regs[jit.stack_depth - 1] = reg2;
                    jit.stack_regs[jit.stack_depth - 2] = reg1;
                }
                break;
            }
            
            // VFM_DIV is intentionally DECLINED. The interpreter's op_div checks
            // for a zero divisor and returns VFM_ERROR_DIVISION_BY_ZERO; the only
            // faithful x86 encoding (DIV r64) instead raises #DE and crashes the
            // process on a zero divisor. Because the divisor can be packet-driven,
            // the JIT cannot prove it non-zero, so rather than emit code that
            // diverges from the oracle (crash vs. error return) we bail to the
            // bounds-checked interpreter, which handles division-by-zero safely.
            case VFM_DIV:
                goto decline;

            case VFM_ADD:
            case VFM_SUB:
            case VFM_MUL:
            case VFM_AND:
            case VFM_OR:
            case VFM_XOR: {
                if (jit.stack_depth >= 2) {
                    uint8_t reg_b = jit.stack_regs[--jit.stack_depth];
                    uint8_t reg_a = jit.stack_regs[jit.stack_depth - 1];

                    switch (opcode) {
                        case VFM_ADD: emit_add_reg_reg(&jit, reg_a, reg_b); break;
                        case VFM_SUB: emit_sub_reg_reg(&jit, reg_a, reg_b); break;
                        case VFM_MUL:
                            // Move to RAX for multiply; MUL r64 computes
                            // RDX:RAX = RAX * reg_b, and we keep the low 64 bits
                            // (matching the interpreter's a * b wraparound). RAX
                            // and RDX are scratch here -- the operand stack only
                            // ever lives in R8-R15 -- so clobbering them is safe.
                            emit_mov_reg_reg(&jit, RAX, reg_a);
                            emit_mul_reg(&jit, reg_b);
                            emit_mov_reg_reg(&jit, reg_a, RAX);
                            break;
                        case VFM_AND: emit_and_reg_reg(&jit, reg_a, reg_b); break;
                        case VFM_OR:  emit_or_reg_reg(&jit, reg_a, reg_b); break;
                        case VFM_XOR: emit_xor_reg_reg(&jit, reg_a, reg_b); break;
                    }

                    free_reg(&jit, reg_b);
                }
                break;
            }
            
            case VFM_SHL:
            case VFM_SHR: {
                if (jit.stack_depth >= 2) {
                    uint8_t shift_reg = jit.stack_regs[--jit.stack_depth];
                    uint8_t value_reg = jit.stack_regs[jit.stack_depth - 1];
                    
                    // Move shift amount to CL
                    emit_mov_reg_reg(&jit, RCX, shift_reg);
                    
                    if (opcode == VFM_SHL) {
                        emit_shl_reg_cl(&jit, value_reg);
                    } else {
                        emit_shr_reg_cl(&jit, value_reg);
                    }
                    
                    free_reg(&jit, shift_reg);
                }
                break;
            }
            
            case VFM_NOT:
            case VFM_NEG: {
                if (jit.stack_depth > 0) {
                    uint8_t reg = jit.stack_regs[jit.stack_depth - 1];
                    
                    if (opcode == VFM_NOT) {
                        emit_not_reg(&jit, reg);
                    } else {
                        emit_neg_reg(&jit, reg);
                    }
                }
                break;
            }
            
            // All control-flow opcodes are DECLINED. The previous emitters
            // computed the x86 branch displacement as `vfm_offset * 16` -- a
            // "rough estimate" that does not correspond to any real instruction
            // boundary, so the branch landed at an arbitrary address. The signed
            // conditional jumps (JG/JL) were also wrong for the interpreter's
            // UNSIGNED comparisons (a > b on uint64). Correct branching requires
            // a two-pass VFM-pc -> x86-offset label/fixup map that this compiler
            // does not implement. Rather than emit a branch to a bogus target,
            // decline and let the interpreter run the program correctly.
            case VFM_JEQ:
            case VFM_JNE:
            case VFM_JGT:
            case VFM_JLT:
            case VFM_JMP:
                goto decline;
            
            // 128-bit opcodes are DECLINED. The interpreter models the 128-bit
            // operand stack as two 64-bit slots pushed high-then-low and its
            // EQ128 pops four slots and pushes a boolean; the previous x86
            // emitters modelled this with an inconsistent slot order and, in the
            // scalar EQ128 path, hard-coded relative jump displacements (jne +20,
            // jne +8) that must exactly match the emitted instruction lengths --
            // fragile, unverified, and not proven against the oracle. PUSH128 is
            // already excluded by the jit_compatible pre-scan in vfm.c; LD128 and
            // EQ128 reach here, so we decline them and let the interpreter (which
            // implements the 128-bit semantics correctly) run the program.
            case VFM_LD128:
            case VFM_PUSH128:
            case VFM_EQ128:
                goto decline;

            case VFM_IPV6_EXT: {
                pc += 1;  // consume the field-type operand

                // The JIT cannot correctly extract IPv6 extension-header
                // fields (e.g. L4 ports walked past extension headers), so
                // clean up and bail to the bounds-checked interpreter, which
                // implements this correctly. This is effectively unreachable
                // via vfm_load_program today -- VFM_IPV6_EXT is blocklisted in
                // the jit_compatible pre-scan (src/vfm.c) -- so this is a
                // robustness/consistency change, not an alteration of the
                // IPv6 path. Previously this emitted a fragile runtime -1
                // sentinel; a compile-time bail matches the default case and
                // the stack-overflow precedent (PR #9).
                goto decline;
            }

            case VFM_RET: {
                // Move return value to RAX
                if (jit.stack_depth > 0) {
                    uint8_t reg = jit.stack_regs[--jit.stack_depth];
                    emit_mov_reg_reg(&jit, RAX, reg);
                } else {
                    emit_mov_reg_imm64(&jit, RAX, 0);
                }
                
                emit_epilogue(&jit);
                goto done;
            }
            
            default:
                // This opcode cannot be correctly compiled by the x86-64
                // JIT. The old code emitted `mov RAX, 0` + epilogue, which
                // silently returned 0 (DROP) for every packet -- a silent
                // wrong answer. Instead, clean up partial state and return
                // NULL so vfm_load_program leaves vm->cold.jit_code == NULL
                // and execution falls back to the bounds-checked interpreter,
                // which handles every opcode correctly. Identical shape to
                // the merged stack-overflow bail above (PR #9).
                goto decline;
        }
    }
    
    // Default return if no explicit RET
    emit_mov_reg_imm64(&jit, RAX, 0);
    emit_epilogue(&jit);
    
done:
    free(jit.labels);

    // Make memory executable only (for security)
    if (mprotect(code, code_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(code, code_size);
        return NULL;
    }

    return code;

decline:
    // Shared bail-out: an opcode this compiler cannot prove correct against the
    // interpreter oracle (control flow, DIV, 128-bit ops), register exhaustion,
    // or an unknown opcode. Release the partial page and labels and return NULL
    // so vfm_load_program leaves jit_code == NULL and runs the interpreter. The
    // `return code` above makes this label unreachable by fall-through.
    free(jit.labels);
    munmap(code, code_size);
    return NULL;
}

// Phase 3.2.3: Adaptive x86_64 JIT compilation with packet pattern optimization
void* vfm_jit_compile_x86_64_adaptive(const uint8_t *program, uint32_t len, 
                                      vfm_execution_profile_t *profile) {
    // x86-64 adaptive is intentionally IDENTICAL to single-core on ALL
    // platforms (not just Linux). Until profile-guided x86 emitters are each
    // oracle-validated, adaptive returns the proven single-core page rather
    // than a separate, unverified code generator -- the honest "decline, never
    // emit unverified code" stance. The single-core page is a correct JIT (or
    // NULL -> interpreter fallback), so recompilation still swaps in a valid
    // page and the pointer still changes, satisfying the adaptive contract.
    // x86 PGO is deferred to a follow-up with its own oracle tests.
    (void)profile;
    return vfm_jit_compile_x86_64(program, len);
    
    // Check CPU capabilities for adaptive instruction selection
    x86_64_caps_t caps;
    detect_cpu_capabilities(&caps);
    
    size_t code_size = len * 32; // Conservative estimate
    void *code = mmap(NULL, code_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (code == MAP_FAILED) {
        return NULL;
    }
    
    x86_64_jit_t jit = {
        .code = (uint8_t*)code,
        .code_pos = 0,
        .code_size = code_size,
        .caps = caps
    };
    
    emit_prologue(&jit);
    
    // Phase 3.2.3: Adaptive instruction selection based on packet patterns
    bool use_avx2_ipv4 = false;
    bool use_avx2_ipv6 = false;
    bool use_prefetch_bursts = false;
    bool use_bmi_optimizations = false;
    
    // Analyze packet patterns to select optimal instruction sequences
    if (profile->packet_patterns.total_packets > 1000) {
        uint64_t total = profile->packet_patterns.total_packets;
        
        // IPv4 optimization: Use AVX2 for parallel processing
        if (caps.has_avx2 && (profile->packet_patterns.ipv4_packets * 100 / total) > 80) {
            use_avx2_ipv4 = true;
        }
        
        // IPv6 optimization: Use AVX2 256-bit operations for IPv6 addresses
        if (caps.has_avx2 && (profile->packet_patterns.ipv6_packets * 100 / total) > 80) {
            use_avx2_ipv6 = true;
        }
        
        // Burst optimization: Use prefetch instructions
        if (caps.has_prefetch && (profile->packet_patterns.burst_packets * 100 / total) > 40) {
            use_prefetch_bursts = true;
        }
        
        // BMI optimization: Use bit manipulation instructions for masks and shifts
        if (caps.has_bmi1 && caps.has_bmi2) {
            use_bmi_optimizations = true;
        }
    }
    
    // Emit specialized instruction sequences based on patterns
    uint32_t pc = 0;
    while (pc < len) {
        uint8_t opcode = program[pc];
        
        switch (opcode) {
            case VFM_EQ32:
                if (use_avx2_ipv4) {
                    // AVX2-optimized IPv4 address comparison
                    emit_vmovdqu_ymm_mem(&jit, 0, RSI, 0);  // vmovdqu ymm0, [rsi]
                    emit_vmovdqu_ymm_mem(&jit, 1, RDI, 0);  // vmovdqu ymm1, [rdi]
                    emit_vpcmpeqd_ymm(&jit, 0, 0, 1);       // vpcmpeqd ymm0, ymm0, ymm1
                    emit_vpmovmskb_reg_ymm(&jit, RAX, 0);   // vpmovmskb eax, ymm0
                    // Test if all bytes are equal
                    emit_cmp_reg_imm32(&jit, RAX, 0xFFFFFFFF);
                    emit_sete_reg(&jit, RAX);
                } else {
                    // Standard 32-bit comparison
                    emit_mov_reg_mem32(&jit, RAX, RSI, 0); // mov eax, [rsi]
                    emit_cmp_reg_mem32(&jit, RAX, RDI, 0); // cmp eax, [rdi]
                    emit_sete_reg(&jit, RAX);               // sete al
                }
                break;
                
            case VFM_EQ128:
                if (use_avx2_ipv6) {
                    // AVX2-optimized IPv6 address comparison
                    emit_vmovdqu_xmm_mem(&jit, 0, RSI, 0);  // vmovdqu xmm0, [rsi]
                    emit_vmovdqu_xmm_mem(&jit, 1, RDI, 0);  // vmovdqu xmm1, [rdi]
                    emit_vpcmpeqb_xmm(&jit, 0, 0, 1);       // vpcmpeqb xmm0, xmm0, xmm1
                    emit_vpmovmskb_reg_xmm(&jit, RAX, 0);   // vpmovmskb eax, xmm0
                    // Test if all 16 bytes are equal
                    emit_cmp_reg_imm32(&jit, RAX, 0xFFFF);
                    emit_sete_reg(&jit, RAX);
                } else {
                    // Standard 128-bit comparison using SSE2
                    emit_movdqu_xmm_mem(&jit, 0, RSI, 0);  // movdqu xmm0, [rsi]
                    emit_movdqu_xmm_mem(&jit, 1, RDI, 0);  // movdqu xmm1, [rdi]
                    emit_pcmpeqb_xmm(&jit, 0, 1);          // pcmpeqb xmm0, xmm1
                    emit_pmovmskb_reg_xmm(&jit, RAX, 0);   // pmovmskb eax, xmm0
                    emit_cmp_reg_imm32(&jit, RAX, 0xFFFF);
                    emit_sete_reg(&jit, RAX);
                }
                break;
                
            case VFM_PUSH32:
                if (use_prefetch_bursts) {
                    // Burst-optimized push with prefetching
                    emit_prefetcht0_mem(&jit, RSI, 64);    // prefetcht0 [rsi + 64]
                    emit_mov_reg_mem32(&jit, RAX, RSI, 0); // mov eax, [rsi]
                    emit_mov_mem32_reg(&jit, RDI, 0, RAX); // mov [rdi], eax
                    emit_add_reg_imm(&jit, RDI, 4);        // add rdi, 4
                } else {
                    // Standard push
                    emit_mov_reg_mem32(&jit, RAX, RSI, 0); // mov eax, [rsi]
                    emit_mov_mem32_reg(&jit, RDI, 0, RAX); // mov [rdi], eax
                }
                break;
                
            case VFM_AND32:
                if (use_bmi_optimizations) {
                    // Use BMI instructions for bit manipulation
                    emit_mov_reg_mem32(&jit, RAX, RSI, 0); // mov eax, [rsi]
                    emit_mov_reg_mem32(&jit, RCX, RDI, 0); // mov ecx, [rdi]
                    emit_andn_reg_reg_reg(&jit, RAX, RAX, RCX); // andn eax, eax, ecx
                } else {
                    // Standard AND operation
                    emit_mov_reg_mem32(&jit, RAX, RSI, 0); // mov eax, [rsi]
                    emit_and_reg_mem32(&jit, RAX, RDI, 0); // and eax, [rdi]
                }
                break;
                
            default:
                // Use hot path optimization for frequently executed instructions
                bool is_hot_path = false;
                for (uint32_t i = 0; i < profile->hot_path_count; i++) {
                    if (profile->hot_paths[i] == pc) {
                        is_hot_path = true;
                        break;
                    }
                }
                
                if (is_hot_path && use_prefetch_bursts) {
                    // Add prefetch hints for hot paths
                    emit_prefetcht0_mem(&jit, RSI, 32);
                }
                
                // Standard opcode handling (simplified)
                emit_nop(&jit); // nop (placeholder)
                break;
        }
        
        pc += vfm_instruction_size(opcode);
        if (pc >= len) break;
    }
    
    // Default return 0
    emit_mov_reg_imm64(&jit, RAX, 0);
    emit_epilogue(&jit);
    
    // Make memory executable
    if (mprotect(code, code_size, PROT_READ | PROT_EXEC) != 0) {
        munmap(code, code_size);
        return NULL;
    }
    
    return code;
}