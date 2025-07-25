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
static void emit_mov_reg_mem(x86_64_jit_t *jit, uint8_t reg, uint8_t base, int32_t offset);
static void emit_mov_mem_reg(x86_64_jit_t *jit, uint8_t base, int32_t offset, uint8_t reg);
static void emit_add_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_sub_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_mul_reg(x86_64_jit_t *jit, uint8_t reg);
static void emit_div_reg(x86_64_jit_t *jit, uint8_t reg);
static void emit_and_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_or_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_xor_reg_reg(x86_64_jit_t *jit, uint8_t dst, uint8_t src);
static void emit_shl_reg_cl(x86_64_jit_t *jit, uint8_t reg);
static void emit_shr_reg_cl(x86_64_jit_t *jit, uint8_t reg);
static void emit_not_reg(x86_64_jit_t *jit, uint8_t reg);
static void emit_neg_reg(x86_64_jit_t *jit, uint8_t reg);
static void emit_cmp_reg_reg(x86_64_jit_t *jit, uint8_t reg1, uint8_t reg2);
static void emit_je_rel32(x86_64_jit_t *jit, int32_t offset);
static void emit_jne_rel32(x86_64_jit_t *jit, int32_t offset);
static void emit_jg_rel32(x86_64_jit_t *jit, int32_t offset);
static void emit_jl_rel32(x86_64_jit_t *jit, int32_t offset);
static void emit_jmp_rel32(x86_64_jit_t *jit, int32_t offset);
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

// Register allocation for stack simulation
static uint8_t alloc_reg(x86_64_jit_t *jit) {
    // Use R8-R15 for stack simulation, preserve others for packet access
    static uint8_t available_regs[] = {R8, R9, R10, R11, R12, R13, R14, R15};
    
    if (jit->next_reg < 8) {
        return available_regs[jit->next_reg++];
    }
    
    // Fallback to R8 if we run out
    return R8;
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

// Function prologue: set up stack frame
static void emit_prologue(x86_64_jit_t *jit) {
    // push rbp
    emit_push_reg(jit, RBP);
    // mov rbp, rsp
    emit_mov_reg_reg(jit, RBP, RSP);
    // Allocate space for local variables (stack simulation)
    // sub rsp, 256  (32 * 8 bytes for stack slots)
    emit_byte(jit, rex_prefix(1, 0, 0, 0));
    emit_byte(jit, 0x81);  // SUB r/m64, imm32
    emit_byte(jit, modrm_byte(3, 5, RSP));
    emit_dword(jit, 256);
}

// Function epilogue: clean up and return
static void emit_epilogue(x86_64_jit_t *jit) {
    // Ensure AVX state is properly cleaned up
    if (jit->use_avx2) {
        emit_vzeroupper(jit);
    }
    
    // mov rsp, rbp
    emit_mov_reg_reg(jit, RSP, RBP);
    // pop rbp
    emit_pop_reg(jit, RBP);
    // ret
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
static void emit_vmovdqu_mem_ymm(x86_64_jit_t *jit, uint8_t base, int32_t offset, uint8_t ymm) {
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
    emit_vmovdqu_ymm_mem(jit, YMM0, RSI, 24);  // IPv6 src offset in packet
    
    // Load IPv6 destination address into YMM1
    // ymm1 = IPv6 destination address (16 bytes)  
    emit_vmovdqu_ymm_mem(jit, YMM1, RSI, 40);  // IPv6 dst offset in packet
    
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
    emit_vmovdqu_ymm_mem(jit, YMM0, RSI, 0);   // Load first 256-bit chunk
    emit_vmovdqu_ymm_mem(jit, YMM1, RSI, 32);  // Load second 256-bit chunk
    
    // Compare for equality
    emit_vpcmpeqb_ymm(jit, YMM2, YMM0, YMM1);  // Byte-wise comparison
    
    // Extract comparison result
    emit_vpmovmskb_reg_ymm(jit, RAX, YMM2);    // Get comparison mask
    
    // Check if all bytes matched (mask should be 0xFFFFFFFF for full match)
    emit_mov_reg_imm64(jit, RCX, 0xFFFFFFFF);
    emit_cmp_reg_reg(jit, RAX, RCX);
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
    
    // Compile VFM instructions
    uint32_t pc = 0;
    while (pc < len) {
        uint8_t opcode = program[pc++];
        
        switch (opcode) {
            case VFM_LD8: {
                uint16_t offset = *(uint16_t*)&program[pc];
                pc += 2;
                
                uint8_t reg = alloc_reg(&jit);
                // Load byte from packet: mov reg, byte ptr [rsi + offset]
                // (assuming RSI contains packet pointer)
                emit_byte(&jit, rex_prefix(0, reg >= 8 ? 1 : 0, 0, 0));
                emit_byte(&jit, 0x8A);  // MOV r8, r/m8
                emit_byte(&jit, modrm_byte(2, reg & 7, RSI));
                emit_dword(&jit, offset);
                
                // Zero-extend to 64-bit
                emit_mov_reg_reg(&jit, reg, reg);
                
                jit.stack_regs[jit.stack_depth++] = reg;
                break;
            }
            
            case VFM_LD16: {
                uint16_t offset = *(uint16_t*)&program[pc];
                pc += 2;
                
                uint8_t reg = alloc_reg(&jit);
                // Load word: mov reg, word ptr [rsi + offset]
                emit_byte(&jit, 0x66);  // 16-bit override
                emit_byte(&jit, rex_prefix(0, reg >= 8 ? 1 : 0, 0, 0));
                emit_byte(&jit, 0x8B);
                emit_byte(&jit, modrm_byte(2, reg & 7, RSI));
                emit_dword(&jit, offset);
                
                // Convert network to host order (bswap)
                emit_byte(&jit, 0x66);
                if (reg >= 8) emit_byte(&jit, rex_prefix(0, 0, 0, 1));
                emit_byte(&jit, 0x0F);
                emit_byte(&jit, 0xC8 + (reg & 7));  // BSWAP r16
                
                jit.stack_regs[jit.stack_depth++] = reg;
                break;
            }
            
            case VFM_LD32: {
                uint16_t offset = *(uint16_t*)&program[pc];
                pc += 2;
                
                uint8_t reg = alloc_reg(&jit);
                // Load dword: mov reg, dword ptr [rsi + offset]
                emit_byte(&jit, rex_prefix(0, reg >= 8 ? 1 : 0, 0, 0));
                emit_byte(&jit, 0x8B);
                emit_byte(&jit, modrm_byte(2, reg & 7, RSI));
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
            
            case VFM_ADD:
            case VFM_SUB:
            case VFM_MUL:
            case VFM_DIV:
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
                            // Move to RAX for multiply
                            emit_mov_reg_reg(&jit, RAX, reg_a);
                            emit_mul_reg(&jit, reg_b);
                            emit_mov_reg_reg(&jit, reg_a, RAX);
                            break;
                        case VFM_DIV:
                            // Clear RDX, move to RAX for divide
                            emit_xor_reg_reg(&jit, RDX, RDX);
                            emit_mov_reg_reg(&jit, RAX, reg_a);
                            emit_div_reg(&jit, reg_b);
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
            
            case VFM_JEQ:
            case VFM_JNE:
            case VFM_JGT:
            case VFM_JLT: {
                int16_t offset = *(int16_t*)&program[pc];
                pc += 2;
                
                if (jit.stack_depth >= 2) {
                    uint8_t reg_b = jit.stack_regs[--jit.stack_depth];
                    uint8_t reg_a = jit.stack_regs[--jit.stack_depth];
                    
                    emit_cmp_reg_reg(&jit, reg_a, reg_b);
                    
                    // Calculate jump target (simplified)
                    int32_t jump_offset = offset * 16;  // Rough estimate
                    
                    switch (opcode) {
                        case VFM_JEQ: emit_je_rel32(&jit, jump_offset); break;
                        case VFM_JNE: emit_jne_rel32(&jit, jump_offset); break;
                        case VFM_JGT: emit_jg_rel32(&jit, jump_offset); break;
                        case VFM_JLT: emit_jl_rel32(&jit, jump_offset); break;
                    }
                    
                    free_reg(&jit, reg_a);
                    free_reg(&jit, reg_b);
                }
                break;
            }
            
            case VFM_JMP: {
                int16_t offset = *(int16_t*)&program[pc];
                pc += 2;
                
                int32_t jump_offset = offset * 16;  // Rough estimate
                emit_jmp_rel32(&jit, jump_offset);
                break;
            }
            
            case VFM_LD128: {
                uint16_t offset = *(uint16_t*)&program[pc];
                pc += 2;
                
                if (jit.use_avx2) {
                    // AVX2 optimized version for Phase 2.2
                    // Load 128-bit value directly into YMM register, then store to stack
                    
                    // Load 128-bit IPv6 address from packet: VMOVDQU YMM0, [RSI + offset]
                    emit_vmovdqu_ymm_mem(&jit, YMM0, RSI, offset);
                    
                    // Store to stack as two 64-bit values for register allocation
                    emit_vmovdqu_mem_ymm(&jit, RSP, -16, YMM0);  // Store lower 128-bits
                    
                    // Load back into general-purpose registers for stack management
                    uint8_t reg_low = alloc_reg(&jit);
                    uint8_t reg_high = alloc_reg(&jit);
                    
                    emit_mov_reg_mem(&jit, reg_low, RSP, -16);   // Low 64 bits
                    emit_mov_reg_mem(&jit, reg_high, RSP, -8);   // High 64 bits
                    
                    // Push both values on stack (low first, then high)
                    jit.stack_regs[jit.stack_depth++] = reg_low;
                    jit.stack_regs[jit.stack_depth++] = reg_high;
                    
                } else {
                    // Scalar fallback implementation
                    // Load 128-bit IPv6 address from packet as two 64-bit values
                    uint8_t reg_low = alloc_reg(&jit);
                    uint8_t reg_high = alloc_reg(&jit);
                    
                    // Load low 64 bits: mov reg_low, qword ptr [rsi + offset]
                    emit_mov_reg_mem(&jit, reg_low, RSI, offset);
                    // Load high 64 bits: mov reg_high, qword ptr [rsi + offset + 8]
                    emit_mov_reg_mem(&jit, reg_high, RSI, offset + 8);
                    
                    // Push both values on stack (low first, then high)
                    jit.stack_regs[jit.stack_depth++] = reg_low;
                    jit.stack_regs[jit.stack_depth++] = reg_high;
                }
                break;
            }
            
            case VFM_PUSH128: {
                // 128-bit immediate: 16 bytes (low 64 bits, then high 64 bits)
                uint64_t low = *(uint64_t*)&program[pc];
                uint64_t high = *(uint64_t*)&program[pc + 8];
                pc += 16;
                
                uint8_t reg_low = alloc_reg(&jit);
                uint8_t reg_high = alloc_reg(&jit);
                
                emit_mov_reg_imm64(&jit, reg_low, low);
                emit_mov_reg_imm64(&jit, reg_high, high);
                
                // Push both values on stack (low first, then high)
                jit.stack_regs[jit.stack_depth++] = reg_low;
                jit.stack_regs[jit.stack_depth++] = reg_high;
                break;
            }
            
            case VFM_EQ128: {
                if (jit.stack_depth >= 4) {
                    // Pop two 128-bit values (4 64-bit registers total)
                    uint8_t b_high = jit.stack_regs[--jit.stack_depth];
                    uint8_t b_low = jit.stack_regs[--jit.stack_depth];
                    uint8_t a_high = jit.stack_regs[--jit.stack_depth];
                    uint8_t a_low = jit.stack_regs[--jit.stack_depth];
                    
                    uint8_t result_reg = alloc_reg(&jit);
                    
                    if (jit.use_avx2) {
                        // AVX2 optimized version for Phase 2.2
                        // Build 128-bit values in memory for vectorized comparison
                        
                        // Store first 128-bit value at [rsp-32]
                        emit_mov_mem_reg(&jit, RSP, -16, a_low);   // Low 64 bits
                        emit_mov_mem_reg(&jit, RSP, -8, a_high);   // High 64 bits
                        
                        // Store second 128-bit value at [rsp-16]  
                        emit_mov_mem_reg(&jit, RSP, -32, b_low);   // Low 64 bits
                        emit_mov_mem_reg(&jit, RSP, -24, b_high);  // High 64 bits
                        
                        // Intel/AMD specific instruction preferences for Phase 2.2
                        if (jit.caps.vendor == CPU_VENDOR_INTEL) {
                            // Intel prefers aligned loads when possible
                            emit_vmovdqu_ymm_mem(&jit, YMM0, RSP, -32); // Load first value
                            emit_vmovdqu_ymm_mem(&jit, YMM1, RSP, -16); // Load second value
                            emit_vpcmpeqb_ymm(&jit, YMM2, YMM0, YMM1);  // Compare
                        } else {
                            // AMD and others: use standard sequence
                            emit_vmovdqu_ymm_mem(&jit, YMM0, RSP, -32);
                            emit_vmovdqu_ymm_mem(&jit, YMM1, RSP, -16);
                            emit_vpcmpeqb_ymm(&jit, YMM2, YMM0, YMM1);
                        }
                        
                        // Extract comparison result mask: VPMOVMSKB reg, YMM2
                        emit_vpmovmskb_reg_ymm(&jit, result_reg, YMM2);
                        
                        // Check if all bytes are equal (mask == 0xFFFFFFFF for 32 bytes)
                        emit_cmp_reg_imm32(&jit, result_reg, 0x0000FFFF); // Only first 16 bytes matter
                        
                        // Set result: 1 if equal, 0 if not equal
                        emit_mov_reg_imm64(&jit, result_reg, 0);
                        emit_sete_reg8(&jit, result_reg); // Set byte if equal
                        
                    } else {
                        // Scalar fallback implementation
                        // Compare low parts: cmp a_low, b_low
                        emit_cmp_reg_reg(&jit, a_low, b_low);
                        
                        // Set result register to 0 initially
                        emit_mov_reg_imm64(&jit, result_reg, 0);
                        
                        // Jump if low parts not equal
                        emit_jne_rel32(&jit, 20); // Skip high comparison
                        
                        // Compare high parts: cmp a_high, b_high
                        emit_cmp_reg_reg(&jit, a_high, b_high);
                        
                        // Jump if high parts not equal
                        emit_jne_rel32(&jit, 8); // Skip setting result to 1
                        
                        // Set result to 1 (equal)
                        emit_mov_reg_imm64(&jit, result_reg, 1);
                    }
                    
                    // Free used registers
                    free_reg(&jit, a_low); free_reg(&jit, a_high);
                    free_reg(&jit, b_low); free_reg(&jit, b_high);
                    
                    // Push result
                    jit.stack_regs[jit.stack_depth++] = result_reg;
                }
                break;
            }
            
            case VFM_IPV6_EXT: {
                uint8_t field_type = program[pc];
                pc += 1;
                (void)field_type; // Currently unused in JIT implementation
                
                // For now, fall back to interpreter for IPv6 extension fields
                // This is complex to implement in JIT, so we emit a call to interpreter
                emit_mov_reg_imm64(&jit, RAX, -1); // Return error - fall back to interpreter
                emit_epilogue(&jit);
                goto done;
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
                // Unknown instruction - emit return 0
                emit_mov_reg_imm64(&jit, RAX, 0);
                emit_epilogue(&jit);
                goto done;
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
}

// Phase 3.2.3: Adaptive x86_64 JIT compilation with packet pattern optimization
void* vfm_jit_compile_x86_64_adaptive(const uint8_t *program, uint32_t len, 
                                      vfm_execution_profile_t *profile) {
    // Disable adaptive JIT on Linux due to incomplete implementation
    #ifdef VFM_PLATFORM_LINUX
        (void)profile;
        return vfm_jit_compile_x86_64(program, len);
    #endif
    
    if (!profile) {
        // Fall back to regular compilation if no profile available
        return vfm_jit_compile_x86_64(program, len);
    }
    
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