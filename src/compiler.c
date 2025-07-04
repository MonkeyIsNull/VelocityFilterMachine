#include "vfm.h"
#include "opcodes.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Type definitions are now in vfm.h

// Stack simulation for BPF compilation
typedef struct bpf_compiler {
    bpf_insn_t *insns;
    uint32_t insn_count;
    uint32_t max_insns;
    uint32_t stack_depth;
    uint32_t max_stack_depth;
    int32_t *jump_fixups;  // For handling forward jumps
    uint32_t jump_fixup_count;
} bpf_compiler_t;

// BPF instruction codes (classic BPF)
#define BPF_LD      0x00
#define BPF_LDX     0x01
#define BPF_ST      0x02
#define BPF_STX     0x03
#define BPF_ALU     0x04
#define BPF_JMP     0x05
#define BPF_RET     0x06
#define BPF_MISC    0x07

#define BPF_W       0x00
#define BPF_H       0x08
#define BPF_B       0x10
#define BPF_ABS     0x20
#define BPF_IND     0x40
#define BPF_MEM     0x60
#define BPF_LEN     0x80
#define BPF_MSH     0xa0

#define BPF_ADD     0x00
#define BPF_SUB     0x10
#define BPF_MUL     0x20
#define BPF_DIV     0x30
#define BPF_OR      0x40
#define BPF_AND     0x50
#define BPF_LSH     0x60
#define BPF_RSH     0x70
#define BPF_NEG     0x80
#define BPF_MOD     0x90
#define BPF_XOR     0xa0

#define BPF_JA      0x00
#define BPF_JEQ     0x10
#define BPF_JGT     0x20
#define BPF_JGE     0x30
#define BPF_JSET    0x40

#define BPF_K       0x00
#define BPF_X       0x08
#define BPF_A       0x10
#define BPF_IMM     0x00
#define BPF_TAX     0x80
#define BPF_TXA     0x80

// eBPF instruction classes
#define EBPF_LD     0x00
#define EBPF_LDX    0x01
#define EBPF_ST     0x02
#define EBPF_STX    0x03
#define EBPF_ALU    0x04
#define EBPF_JMP    0x05
#define EBPF_RET    0x06
#define EBPF_ALU64  0x07

// eBPF modes
#define EBPF_IMM    0x00
#define EBPF_ABS    0x20
#define EBPF_IND    0x40
#define EBPF_MEM    0x60
#define EBPF_XADD   0xc0

// eBPF sizes
#define EBPF_W      0x00
#define EBPF_H      0x08
#define EBPF_B      0x10
#define EBPF_DW     0x18

// eBPF ALU operations
#define EBPF_ADD    0x00
#define EBPF_SUB    0x10
#define EBPF_MUL    0x20
#define EBPF_DIV    0x30
#define EBPF_OR     0x40
#define EBPF_AND    0x50
#define EBPF_LSH    0x60
#define EBPF_RSH    0x70
#define EBPF_NEG    0x80
#define EBPF_MOD    0x90
#define EBPF_XOR    0xa0
#define EBPF_MOV    0xb0

// eBPF jump operations
#define EBPF_JA     0x00
#define EBPF_JEQ    0x10
#define EBPF_JGT    0x20
#define EBPF_JGE    0x30
#define EBPF_JSET   0x40
#define EBPF_JNE    0x50
#define EBPF_JSGT   0x60
#define EBPF_JSGE   0x70
#define EBPF_CALL   0x80
#define EBPF_EXIT   0x90

// eBPF sources
#define EBPF_K      0x00
#define EBPF_X      0x08

// eBPF registers
#define EBPF_REG_0  0
#define EBPF_REG_1  1
#define EBPF_REG_2  2
#define EBPF_REG_3  3
#define EBPF_REG_4  4
#define EBPF_REG_5  5
#define EBPF_REG_6  6
#define EBPF_REG_7  7
#define EBPF_REG_8  8
#define EBPF_REG_9  9
#define EBPF_REG_10 10  // Stack pointer

// Helper functions for BPF compilation
static int emit_bpf(bpf_compiler_t *c, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k);
static int compile_stack_op(bpf_compiler_t *c, uint8_t op);
static int simulate_stack_push(bpf_compiler_t *c);
static int simulate_stack_pop(bpf_compiler_t *c);
static int fixup_jumps(bpf_compiler_t *c, uint32_t *label_map, uint32_t label_count);

// Helper function to emit BPF instruction
static int emit_bpf(bpf_compiler_t *c, uint16_t code, uint8_t jt, uint8_t jf, uint32_t k) {
    if (c->insn_count >= c->max_insns) {
        return VFM_ERROR_NO_MEMORY;
    }
    
    c->insns[c->insn_count++] = (bpf_insn_t){
        .code = code,
        .jt = jt,
        .jf = jf,
        .k = k
    };
    
    return VFM_SUCCESS;
}

// Simulate stack push for BPF compilation
static int simulate_stack_push(bpf_compiler_t *c) {
    if (c->stack_depth >= 16) {  // BPF memory is limited
        return VFM_ERROR_STACK_OVERFLOW;
    }
    
    // Store accumulator to memory slot
    int result = emit_bpf(c, BPF_ST, 0, 0, c->stack_depth);
    if (result != VFM_SUCCESS) return result;
    
    c->stack_depth++;
    if (c->stack_depth > c->max_stack_depth) {
        c->max_stack_depth = c->stack_depth;
    }
    
    return VFM_SUCCESS;
}

// Simulate stack pop for BPF compilation
static int simulate_stack_pop(bpf_compiler_t *c) {
    if (c->stack_depth == 0) {
        return VFM_ERROR_STACK_UNDERFLOW;
    }
    
    c->stack_depth--;
    
    // Load from memory slot to accumulator
    return emit_bpf(c, BPF_LD | BPF_MEM, 0, 0, c->stack_depth);
}

// Compile VFM to classic BPF with proper stack simulation
int vfm_to_bpf(const uint8_t *vfm_prog, uint32_t vfm_len,
               bpf_insn_t *bpf_prog, uint32_t *bpf_len) {
    if (!vfm_prog || !bpf_prog || !bpf_len) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    bpf_compiler_t compiler = {
        .insns = bpf_prog,
        .insn_count = 0,
        .max_insns = *bpf_len,
        .stack_depth = 0,
        .max_stack_depth = 0,
        .jump_fixups = NULL,
        .jump_fixup_count = 0
    };
    
    uint32_t vfm_pc = 0;
    int result = VFM_SUCCESS;
    
    while (vfm_pc < vfm_len && result == VFM_SUCCESS) {
        uint8_t opcode = vfm_prog[vfm_pc++];
        
        switch (opcode) {
            case VFM_LD8: {
                uint16_t offset = *(uint16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                result = emit_bpf(&compiler, BPF_LD | BPF_B | BPF_ABS, 0, 0, offset);
                if (result == VFM_SUCCESS) {
                    result = simulate_stack_push(&compiler);
                }
                break;
            }
            
            case VFM_LD16: {
                uint16_t offset = *(uint16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                result = emit_bpf(&compiler, BPF_LD | BPF_H | BPF_ABS, 0, 0, offset);
                if (result == VFM_SUCCESS) {
                    result = simulate_stack_push(&compiler);
                }
                break;
            }
            
            case VFM_LD32: {
                uint16_t offset = *(uint16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                result = emit_bpf(&compiler, BPF_LD | BPF_W | BPF_ABS, 0, 0, offset);
                if (result == VFM_SUCCESS) {
                    result = simulate_stack_push(&compiler);
                }
                break;
            }
            
            case VFM_PUSH: {
                uint64_t value = *(uint64_t*)&vfm_prog[vfm_pc];
                vfm_pc += 8;
                
                result = emit_bpf(&compiler, BPF_LD | BPF_IMM, 0, 0, (uint32_t)value);
                if (result == VFM_SUCCESS) {
                    result = simulate_stack_push(&compiler);
                }
                break;
            }
            
            case VFM_POP: {
                result = simulate_stack_pop(&compiler);
                break;
            }
            
            case VFM_DUP: {
                // Duplicate top of stack: pop, push twice
                result = simulate_stack_pop(&compiler);
                if (result == VFM_SUCCESS) {
                    result = simulate_stack_push(&compiler);
                }
                if (result == VFM_SUCCESS) {
                    result = simulate_stack_push(&compiler);
                }
                break;
            }
            
            case VFM_SWAP: {
                // Swap top two: complex in BPF, need temp memory
                if (compiler.stack_depth < 2) {
                    result = VFM_ERROR_STACK_UNDERFLOW;
                    break;
                }
                
                // Load top
                result = simulate_stack_pop(&compiler);
                if (result != VFM_SUCCESS) break;
                
                // Store to temp location
                result = emit_bpf(&compiler, BPF_ST, 0, 0, 15);  // Use slot 15 as temp
                if (result != VFM_SUCCESS) break;
                
                // Load second
                result = simulate_stack_pop(&compiler);
                if (result != VFM_SUCCESS) break;
                
                // Push as new top
                result = simulate_stack_push(&compiler);
                if (result != VFM_SUCCESS) break;
                
                // Load temp and push
                result = emit_bpf(&compiler, BPF_LD | BPF_MEM, 0, 0, 15);
                if (result != VFM_SUCCESS) break;
                
                result = simulate_stack_push(&compiler);
                break;
            }
            
            case VFM_ADD:
            case VFM_SUB:
            case VFM_MUL:
            case VFM_DIV:
            case VFM_AND:
            case VFM_OR:
            case VFM_XOR:
            case VFM_SHL:
            case VFM_SHR: {
                // Binary operations: pop two, perform op, push result
                if (compiler.stack_depth < 2) {
                    result = VFM_ERROR_STACK_UNDERFLOW;
                    break;
                }
                
                // Pop second operand to X register
                result = simulate_stack_pop(&compiler);
                if (result != VFM_SUCCESS) break;
                
                result = emit_bpf(&compiler, BPF_TAX, 0, 0, 0);  // Transfer A to X
                if (result != VFM_SUCCESS) break;
                
                // Pop first operand to A
                result = simulate_stack_pop(&compiler);
                if (result != VFM_SUCCESS) break;
                
                // Perform operation
                uint16_t alu_op;
                switch (opcode) {
                    case VFM_ADD: alu_op = BPF_ALU | BPF_ADD | BPF_X; break;
                    case VFM_SUB: alu_op = BPF_ALU | BPF_SUB | BPF_X; break;
                    case VFM_MUL: alu_op = BPF_ALU | BPF_MUL | BPF_X; break;
                    case VFM_DIV: alu_op = BPF_ALU | BPF_DIV | BPF_X; break;
                    case VFM_AND: alu_op = BPF_ALU | BPF_AND | BPF_X; break;
                    case VFM_OR:  alu_op = BPF_ALU | BPF_OR | BPF_X; break;
                    case VFM_XOR: alu_op = BPF_ALU | BPF_XOR | BPF_X; break;
                    case VFM_SHL: alu_op = BPF_ALU | BPF_LSH | BPF_X; break;
                    case VFM_SHR: alu_op = BPF_ALU | BPF_RSH | BPF_X; break;
                    default: alu_op = 0; break;
                }
                
                result = emit_bpf(&compiler, alu_op, 0, 0, 0);
                if (result != VFM_SUCCESS) break;
                
                // Push result
                result = simulate_stack_push(&compiler);
                break;
            }
            
            case VFM_NOT:
            case VFM_NEG: {
                // Unary operations
                if (compiler.stack_depth < 1) {
                    result = VFM_ERROR_STACK_UNDERFLOW;
                    break;
                }
                
                result = simulate_stack_pop(&compiler);
                if (result != VFM_SUCCESS) break;
                
                if (opcode == VFM_NOT) {
                    // XOR with all 1s
                    result = emit_bpf(&compiler, BPF_ALU | BPF_XOR | BPF_K, 0, 0, 0xFFFFFFFF);
                } else {
                    // NEG operation
                    result = emit_bpf(&compiler, BPF_ALU | BPF_NEG, 0, 0, 0);
                }
                
                if (result != VFM_SUCCESS) break;
                result = simulate_stack_push(&compiler);
                break;
            }
            
            case VFM_JEQ:
            case VFM_JNE:
            case VFM_JGT:
            case VFM_JLT:
            case VFM_JGE:
            case VFM_JLE: {
                int16_t offset = *(int16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                if (compiler.stack_depth < 2) {
                    result = VFM_ERROR_STACK_UNDERFLOW;
                    break;
                }
                
                // Pop comparison values
                result = simulate_stack_pop(&compiler);  // Second value to A
                if (result != VFM_SUCCESS) break;
                
                result = emit_bpf(&compiler, BPF_TAX, 0, 0, 0);  // Transfer A to X
                if (result != VFM_SUCCESS) break;
                
                result = simulate_stack_pop(&compiler);  // First value to A
                if (result != VFM_SUCCESS) break;
                
                // Convert offset to BPF jump distance
                uint8_t jt = (offset > 0) ? (uint8_t)offset : 0;
                uint8_t jf = (offset < 0) ? (uint8_t)(-offset) : 0;
                
                uint16_t jmp_op;
                switch (opcode) {
                    case VFM_JEQ: jmp_op = BPF_JMP | BPF_JEQ | BPF_X; break;
                    case VFM_JNE: jmp_op = BPF_JMP | BPF_JEQ | BPF_X; jt = jf; jf = 0; break;  // Invert
                    case VFM_JGT: jmp_op = BPF_JMP | BPF_JGT | BPF_X; break;
                    case VFM_JLT: jmp_op = BPF_JMP | BPF_JGE | BPF_X; jt = jf; jf = 0; break;  // Invert
                    case VFM_JGE: jmp_op = BPF_JMP | BPF_JGE | BPF_X; break;
                    case VFM_JLE: jmp_op = BPF_JMP | BPF_JGT | BPF_X; jt = jf; jf = 0; break;  // Invert
                    default: jmp_op = 0; break;
                }
                
                result = emit_bpf(&compiler, jmp_op, jt, jf, 0);
                break;
            }
            
            case VFM_JMP: {
                int16_t offset = *(int16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                result = emit_bpf(&compiler, BPF_JMP | BPF_JA, 0, 0, offset);
                break;
            }
            
            case VFM_RET: {
                // Return top of stack
                if (compiler.stack_depth > 0) {
                    result = simulate_stack_pop(&compiler);
                } else {
                    // Return 0 if stack is empty
                    result = emit_bpf(&compiler, BPF_LD | BPF_IMM, 0, 0, 0);
                }
                
                if (result == VFM_SUCCESS) {
                    result = emit_bpf(&compiler, BPF_RET | BPF_A, 0, 0, 0);
                }
                goto done;
            }
            
            default:
                result = VFM_ERROR_INVALID_OPCODE;
                break;
        }
    }
    
done:
    *bpf_len = compiler.insn_count;
    return result;
}

// eBPF compiler state
typedef struct ebpf_compiler {
    ebpf_insn_t *insns;
    uint32_t insn_count;
    uint32_t max_insns;
    uint8_t reg_stack[10];   // R0-R9 for stack simulation
    uint32_t stack_depth;
    uint32_t next_reg;       // Next available register
} ebpf_compiler_t;

// Helper function to emit eBPF instruction
static int emit_ebpf(ebpf_compiler_t *c, uint8_t code, uint8_t dst, uint8_t src, int16_t off, int32_t imm) {
    if (c->insn_count >= c->max_insns) {
        return VFM_ERROR_NO_MEMORY;
    }
    
    c->insns[c->insn_count++] = (ebpf_insn_t){
        .code = code,
        .dst_reg = dst,
        .src_reg = src,
        .off = off,
        .imm = imm
    };
    
    return VFM_SUCCESS;
}

// Allocate register for eBPF stack simulation
static uint8_t alloc_reg(ebpf_compiler_t *c) {
    if (c->next_reg >= 9) {  // R0-R9, R10 is stack pointer
        return EBPF_REG_0;  // Fallback to R0
    }
    return c->next_reg++;
}

// Compile VFM to eBPF
int vfm_to_ebpf(const uint8_t *vfm_prog, uint32_t vfm_len, ebpf_insn_t *ebpf_prog, uint32_t *ebpf_len) {
    if (!vfm_prog || !ebpf_prog || !ebpf_len) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    ebpf_compiler_t compiler = {
        .insns = ebpf_prog,
        .insn_count = 0,
        .max_insns = *ebpf_len,
        .stack_depth = 0,
        .next_reg = 1  // R0 is return value, start with R1
    };
    
    uint32_t vfm_pc = 0;
    int result = VFM_SUCCESS;
    
    while (vfm_pc < vfm_len && result == VFM_SUCCESS) {
        uint8_t opcode = vfm_prog[vfm_pc++];
        
        switch (opcode) {
            case VFM_LD8: {
                uint16_t offset = *(uint16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                uint8_t reg = alloc_reg(&compiler);
                // Load byte from packet data
                result = emit_ebpf(&compiler, EBPF_LDX | EBPF_B | EBPF_MEM, reg, EBPF_REG_1, offset, 0);
                if (result == VFM_SUCCESS) {
                    compiler.reg_stack[compiler.stack_depth++] = reg;
                }
                break;
            }
            
            case VFM_LD16: {
                uint16_t offset = *(uint16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                uint8_t reg = alloc_reg(&compiler);
                result = emit_ebpf(&compiler, EBPF_LDX | EBPF_H | EBPF_MEM, reg, EBPF_REG_1, offset, 0);
                if (result == VFM_SUCCESS) {
                    compiler.reg_stack[compiler.stack_depth++] = reg;
                }
                break;
            }
            
            case VFM_LD32: {
                uint16_t offset = *(uint16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                uint8_t reg = alloc_reg(&compiler);
                result = emit_ebpf(&compiler, EBPF_LDX | EBPF_W | EBPF_MEM, reg, EBPF_REG_1, offset, 0);
                if (result == VFM_SUCCESS) {
                    compiler.reg_stack[compiler.stack_depth++] = reg;
                }
                break;
            }
            
            case VFM_PUSH: {
                uint64_t value = *(uint64_t*)&vfm_prog[vfm_pc];
                vfm_pc += 8;
                
                uint8_t reg = alloc_reg(&compiler);
                result = emit_ebpf(&compiler, EBPF_ALU64 | EBPF_MOV | EBPF_K, reg, 0, 0, (int32_t)value);
                if (result == VFM_SUCCESS) {
                    compiler.reg_stack[compiler.stack_depth++] = reg;
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
                if (compiler.stack_depth < 2) {
                    result = VFM_ERROR_STACK_UNDERFLOW;
                    break;
                }
                
                uint8_t reg_a = compiler.reg_stack[--compiler.stack_depth];
                uint8_t reg_b = compiler.reg_stack[--compiler.stack_depth];
                
                uint8_t alu_op;
                switch (opcode) {
                    case VFM_ADD: alu_op = EBPF_ADD; break;
                    case VFM_SUB: alu_op = EBPF_SUB; break;
                    case VFM_MUL: alu_op = EBPF_MUL; break;
                    case VFM_DIV: alu_op = EBPF_DIV; break;
                    case VFM_AND: alu_op = EBPF_AND; break;
                    case VFM_OR:  alu_op = EBPF_OR; break;
                    case VFM_XOR: alu_op = EBPF_XOR; break;
                    default: alu_op = 0; break;
                }
                
                result = emit_ebpf(&compiler, EBPF_ALU64 | alu_op, reg_b, reg_a, 0, 0);
                if (result == VFM_SUCCESS) {
                    compiler.reg_stack[compiler.stack_depth++] = reg_b;  // Result in reg_b
                }
                break;
            }
            
            case VFM_JEQ:
            case VFM_JNE:
            case VFM_JGT:
            case VFM_JLT: {
                int16_t offset = *(int16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                if (compiler.stack_depth < 2) {
                    result = VFM_ERROR_STACK_UNDERFLOW;
                    break;
                }
                
                uint8_t reg_a = compiler.reg_stack[--compiler.stack_depth];
                uint8_t reg_b = compiler.reg_stack[--compiler.stack_depth];
                
                uint8_t jmp_op;
                switch (opcode) {
                    case VFM_JEQ: jmp_op = EBPF_JEQ; break;
                    case VFM_JNE: jmp_op = EBPF_JNE; break;
                    case VFM_JGT: jmp_op = EBPF_JGT; break;
                    case VFM_JLT: jmp_op = EBPF_JGT; break;  // Swap operands for JLT
                    default: jmp_op = 0; break;
                }
                
                if (opcode == VFM_JLT) {
                    result = emit_ebpf(&compiler, EBPF_JMP | jmp_op, reg_a, reg_b, offset, 0);
                } else {
                    result = emit_ebpf(&compiler, EBPF_JMP | jmp_op, reg_b, reg_a, offset, 0);
                }
                break;
            }
            
            case VFM_RET: {
                if (compiler.stack_depth > 0) {
                    uint8_t reg = compiler.reg_stack[--compiler.stack_depth];
                    result = emit_ebpf(&compiler, EBPF_ALU64 | EBPF_MOV, EBPF_REG_0, reg, 0, 0);
                } else {
                    result = emit_ebpf(&compiler, EBPF_ALU64 | EBPF_MOV | EBPF_K, EBPF_REG_0, 0, 0, 0);
                }
                
                if (result == VFM_SUCCESS) {
                    result = emit_ebpf(&compiler, EBPF_JMP | EBPF_EXIT, 0, 0, 0, 0);
                }
                goto done;
            }
            
            default:
                result = VFM_ERROR_INVALID_OPCODE;
                break;
        }
    }
    
done:
    *ebpf_len = compiler.insn_count;
    return result;
}

// Classic BPF program structure definition is now in vfm.h

int vfm_to_cbpf(const uint8_t *vfm_prog, uint32_t vfm_len, bpf_program_t *prog) {
    if (!vfm_prog || !prog) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    // Allocate BPF instructions
    prog->bf_insns = malloc(vfm_len * 4 * sizeof(bpf_insn_t));  // Conservative estimate
    if (!prog->bf_insns) {
        return VFM_ERROR_NO_MEMORY;
    }
    
    uint32_t max_len = vfm_len * 4;
    int result = vfm_to_bpf(vfm_prog, vfm_len, prog->bf_insns, &max_len);
    
    if (result == VFM_SUCCESS) {
        prog->bf_len = max_len;
    } else {
        free(prog->bf_insns);
        prog->bf_insns = NULL;
        prog->bf_len = 0;
    }
    
    return result;
}

// Generate XDP C code
int vfm_to_xdp(const uint8_t *vfm_prog, uint32_t vfm_len, char *c_code, size_t code_size) {
    if (!vfm_prog || !c_code || code_size == 0) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    size_t pos = 0;
    uint32_t vfm_pc = 0;
    
    // Generate XDP program header
    pos += snprintf(c_code + pos, code_size - pos,
        "#include <linux/bpf.h>\n"
        "#include <linux/if_ether.h>\n"
        "#include <linux/ip.h>\n"
        "#include <linux/tcp.h>\n"
        "#include <linux/udp.h>\n"
        "#include <bpf/bpf_helpers.h>\n\n"
        "SEC(\"xdp\")\n"
        "int vfm_filter(struct xdp_md *ctx) {\n"
        "    void *data_end = (void *)(long)ctx->data_end;\n"
        "    void *data = (void *)(long)ctx->data;\n"
        "    uint64_t stack[16] = {0};\n"
        "    int sp = 0;\n\n");
    
    // Generate instruction implementations
    while (vfm_pc < vfm_len && pos < code_size - 200) {
        uint8_t opcode = vfm_prog[vfm_pc++];
        
        switch (opcode) {
            case VFM_LD8: {
                uint16_t offset = *(uint16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                pos += snprintf(c_code + pos, code_size - pos,
                    "    if (data + %u + 1 > data_end) return XDP_DROP;\n"
                    "    stack[sp++] = *(uint8_t*)(data + %u);\n",
                    offset, offset);
                break;
            }
            
            case VFM_LD16: {
                uint16_t offset = *(uint16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                pos += snprintf(c_code + pos, code_size - pos,
                    "    if (data + %u + 2 > data_end) return XDP_DROP;\n"
                    "    stack[sp++] = __builtin_bswap16(*(uint16_t*)(data + %u));\n",
                    offset, offset);
                break;
            }
            
            case VFM_LD32: {
                uint16_t offset = *(uint16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                pos += snprintf(c_code + pos, code_size - pos,
                    "    if (data + %u + 4 > data_end) return XDP_DROP;\n"
                    "    stack[sp++] = __builtin_bswap32(*(uint32_t*)(data + %u));\n",
                    offset, offset);
                break;
            }
            
            case VFM_PUSH: {
                uint64_t value = *(uint64_t*)&vfm_prog[vfm_pc];
                vfm_pc += 8;
                
                pos += snprintf(c_code + pos, code_size - pos,
                    "    stack[sp++] = %lluULL;\n", value);
                break;
            }
            
            case VFM_ADD:
                pos += snprintf(c_code + pos, code_size - pos,
                    "    stack[sp-2] = stack[sp-2] + stack[sp-1]; sp--;\n");
                break;
                
            case VFM_SUB:
                pos += snprintf(c_code + pos, code_size - pos,
                    "    stack[sp-2] = stack[sp-2] - stack[sp-1]; sp--;\n");
                break;
                
            case VFM_AND:
                pos += snprintf(c_code + pos, code_size - pos,
                    "    stack[sp-2] = stack[sp-2] & stack[sp-1]; sp--;\n");
                break;
                
            case VFM_OR:
                pos += snprintf(c_code + pos, code_size - pos,
                    "    stack[sp-2] = stack[sp-2] | stack[sp-1]; sp--;\n");
                break;
                
            case VFM_JEQ: {
                int16_t offset = *(int16_t*)&vfm_prog[vfm_pc];
                vfm_pc += 2;
                
                pos += snprintf(c_code + pos, code_size - pos,
                    "    if (stack[sp-2] == stack[sp-1]) goto label_%d;\n"
                    "    sp -= 2;\n", (int)vfm_pc + offset);
                break;
            }
            
            case VFM_RET:
                pos += snprintf(c_code + pos, code_size - pos,
                    "    return (sp > 0 && stack[sp-1]) ? XDP_PASS : XDP_DROP;\n");
                goto done;
                
            default:
                // Skip unknown instructions
                break;
        }
    }
    
done:
    pos += snprintf(c_code + pos, code_size - pos,
        "    return XDP_DROP;\n"
        "}\n\n"
        "char _license[] SEC(\"license\") = \"GPL\";\n");
    
    return VFM_SUCCESS;
}