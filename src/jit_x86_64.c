#include "vfm.h"
#include "opcodes.h"
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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

// Basic instruction emission
static void emit_byte(x86_64_jit_t *jit, uint8_t byte) {
    if (jit->code_pos >= jit->code_size) {
        return; // Buffer overflow protection
    }
    jit->code[jit->code_pos++] = byte;
}

static void emit_word(x86_64_jit_t *jit, uint16_t word) {
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
    // mov rsp, rbp
    emit_mov_reg_reg(jit, RSP, RBP);
    // pop rbp
    emit_pop_reg(jit, RBP);
    // ret
    emit_ret(jit);
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
        .label_count = 0
    };
    
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

// Free JIT compiled code
void vfm_jit_free(void *code, size_t size) {
    if (code) {
        munmap(code, size);
    }
}

// JIT function signature
typedef uint64_t (*vfm_jit_func_t)(const uint8_t *packet, uint16_t packet_len);

// Execute JIT compiled code
uint64_t vfm_jit_execute(void *jit_code, const uint8_t *packet, uint16_t packet_len) {
    if (!jit_code || !packet) {
        return 0;
    }
    
    vfm_jit_func_t func = (vfm_jit_func_t)jit_code;
    return func(packet, packet_len);
}