#ifndef VFM_OPCODES_H
#define VFM_OPCODES_H

#include <stdint.h>

enum vfm_opcode {
    // Packet access (bounds-checked)
    VFM_LD8,     // Load byte from packet
    VFM_LD16,    // Load 16-bit (network order)
    VFM_LD32,    // Load 32-bit (network order)
    VFM_LD64,    // Load 64-bit (network order)

    // Stack operations
    VFM_PUSH,    // Push immediate
    VFM_POP,     // Pop value
    VFM_DUP,     // Duplicate top
    VFM_SWAP,    // Swap top two

    // Arithmetic
    VFM_ADD,     // Add top two
    VFM_SUB,     // Subtract
    VFM_MUL,     // Multiply
    VFM_DIV,     // Divide
    VFM_AND,     // Bitwise AND
    VFM_OR,      // Bitwise OR
    VFM_XOR,     // Bitwise XOR
    VFM_SHL,     // Shift left
    VFM_SHR,     // Shift right

    // Control flow
    VFM_JMP,     // Unconditional jump
    VFM_JEQ,     // Jump if equal
    VFM_JNE,     // Jump if not equal
    VFM_JGT,     // Jump if greater
    VFM_JLT,     // Jump if less
    VFM_RET,     // Return with value

    // Special packet ops
    VFM_HASH5,   // Hash 5-tuple
    VFM_CSUM,    // Checksum validation
    VFM_PARSE,   // Parse L3/L4 headers

    // Flow table operations (for stateful filtering)
    VFM_FLOW_LOAD,   // Load value from flow table
    VFM_FLOW_STORE,  // Store value to flow table

    // Additional useful instructions
    VFM_JGE,     // Jump if greater or equal
    VFM_JLE,     // Jump if less or equal
    VFM_NOT,     // Bitwise NOT
    VFM_NEG,     // Arithmetic negation
    VFM_MOD,     // Modulo

    VFM_OPCODE_MAX
};

// Opcode names for disassembly/debugging
static const char *vfm_opcode_names[] = {
    [VFM_LD8]        = "LD8",
    [VFM_LD16]       = "LD16",
    [VFM_LD32]       = "LD32",
    [VFM_LD64]       = "LD64",
    [VFM_PUSH]       = "PUSH",
    [VFM_POP]        = "POP",
    [VFM_DUP]        = "DUP",
    [VFM_SWAP]       = "SWAP",
    [VFM_ADD]        = "ADD",
    [VFM_SUB]        = "SUB",
    [VFM_MUL]        = "MUL",
    [VFM_DIV]        = "DIV",
    [VFM_AND]        = "AND",
    [VFM_OR]         = "OR",
    [VFM_XOR]        = "XOR",
    [VFM_SHL]        = "SHL",
    [VFM_SHR]        = "SHR",
    [VFM_JMP]        = "JMP",
    [VFM_JEQ]        = "JEQ",
    [VFM_JNE]        = "JNE",
    [VFM_JGT]        = "JGT",
    [VFM_JLT]        = "JLT",
    [VFM_RET]        = "RET",
    [VFM_HASH5]      = "HASH5",
    [VFM_CSUM]       = "CSUM",
    [VFM_PARSE]      = "PARSE",
    [VFM_FLOW_LOAD]  = "FLOW_LOAD",
    [VFM_FLOW_STORE] = "FLOW_STORE",
    [VFM_JGE]        = "JGE",
    [VFM_JLE]        = "JLE",
    [VFM_NOT]        = "NOT",
    [VFM_NEG]        = "NEG",
    [VFM_MOD]        = "MOD"
};

// Instruction format helpers
typedef enum {
    VFM_FMT_NONE,      // No operands (e.g., ADD, POP)
    VFM_FMT_IMM8,      // 8-bit immediate
    VFM_FMT_IMM16,     // 16-bit immediate
    VFM_FMT_IMM32,     // 32-bit immediate
    VFM_FMT_IMM64,     // 64-bit immediate
    VFM_FMT_OFFSET16   // 16-bit offset (for jumps and packet access)
} vfm_format_t;

// Opcode format information
static const vfm_format_t vfm_opcode_format[] = {
    [VFM_LD8]        = VFM_FMT_IMM16,    // offset
    [VFM_LD16]       = VFM_FMT_IMM16,    // offset
    [VFM_LD32]       = VFM_FMT_IMM16,    // offset
    [VFM_LD64]       = VFM_FMT_IMM16,    // offset
    [VFM_PUSH]       = VFM_FMT_IMM64,    // value to push
    [VFM_POP]        = VFM_FMT_NONE,
    [VFM_DUP]        = VFM_FMT_NONE,
    [VFM_SWAP]       = VFM_FMT_NONE,
    [VFM_ADD]        = VFM_FMT_NONE,
    [VFM_SUB]        = VFM_FMT_NONE,
    [VFM_MUL]        = VFM_FMT_NONE,
    [VFM_DIV]        = VFM_FMT_NONE,
    [VFM_AND]        = VFM_FMT_NONE,
    [VFM_OR]         = VFM_FMT_NONE,
    [VFM_XOR]        = VFM_FMT_NONE,
    [VFM_SHL]        = VFM_FMT_NONE,
    [VFM_SHR]        = VFM_FMT_NONE,
    [VFM_JMP]        = VFM_FMT_OFFSET16, // jump offset
    [VFM_JEQ]        = VFM_FMT_OFFSET16, // jump offset
    [VFM_JNE]        = VFM_FMT_OFFSET16, // jump offset
    [VFM_JGT]        = VFM_FMT_OFFSET16, // jump offset
    [VFM_JLT]        = VFM_FMT_OFFSET16, // jump offset
    [VFM_RET]        = VFM_FMT_NONE,
    [VFM_HASH5]      = VFM_FMT_NONE,
    [VFM_CSUM]       = VFM_FMT_NONE,
    [VFM_PARSE]      = VFM_FMT_NONE,
    [VFM_FLOW_LOAD]  = VFM_FMT_NONE,
    [VFM_FLOW_STORE] = VFM_FMT_NONE,
    [VFM_JGE]        = VFM_FMT_OFFSET16, // jump offset
    [VFM_JLE]        = VFM_FMT_OFFSET16, // jump offset
    [VFM_NOT]        = VFM_FMT_NONE,
    [VFM_NEG]        = VFM_FMT_NONE,
    [VFM_MOD]        = VFM_FMT_NONE
};

// Get instruction size in bytes
static inline uint32_t vfm_instruction_size(uint8_t opcode) {
    if (opcode >= VFM_OPCODE_MAX) return 0;
    
    switch (vfm_opcode_format[opcode]) {
        case VFM_FMT_NONE:     return 1;
        case VFM_FMT_IMM8:     return 2;
        case VFM_FMT_IMM16:    return 3;
        case VFM_FMT_IMM32:    return 5;
        case VFM_FMT_IMM64:    return 9;
        case VFM_FMT_OFFSET16: return 3;
        default:               return 0;
    }
}

#endif // VFM_OPCODES_H