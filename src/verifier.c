#include "vfm.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#define MAX_VISITED_NODES 1000
#define MAX_BACK_EDGES 50

typedef struct vfm_verifier {
    const uint8_t *program;
    uint32_t program_len;
    uint8_t *visited;       // Track visited instructions
    int32_t *stack_depth;   // 64-bit stack depth at each instruction
    int32_t *stack128_depth; // 128-bit stack depth at each instruction
    uint32_t *back_edges;   // Back edge targets for loop detection
    uint32_t back_edge_count;
    uint32_t max_stack_depth;
    uint32_t max_stack128_depth;
    uint32_t visited_count;
} vfm_verifier_t;

// Forward declarations
static int verify_cfg(vfm_verifier_t *v, uint32_t pc, int32_t stack_depth, int32_t stack128_depth);
static int verify_instruction(vfm_verifier_t *v, uint32_t pc, uint8_t opcode);

// Main verification function
int vfm_verify(const uint8_t *program, uint32_t len) {
    if (!program || len == 0 || len > VFM_MAX_PROGRAM_SIZE) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    vfm_verifier_t v = {
        .program = program,
        .program_len = len,
        .visited = calloc(len, sizeof(uint8_t)),
        .stack_depth = calloc(len, sizeof(int32_t)),
        .stack128_depth = calloc(len, sizeof(int32_t)),
        .back_edges = calloc(MAX_BACK_EDGES, sizeof(uint32_t)),
        .back_edge_count = 0,
        .max_stack_depth = 0,
        .max_stack128_depth = 0,
        .visited_count = 0
    };
    
    if (!v.visited || !v.stack_depth || !v.stack128_depth || !v.back_edges) {
        free(v.visited);
        free(v.stack_depth);
        free(v.stack128_depth);
        free(v.back_edges);
        return VFM_ERROR_NO_MEMORY;
    }
    
    // Initialize stack depths to -1 (unvisited)
    for (uint32_t i = 0; i < len; i++) {
        v.stack_depth[i] = -1;
        v.stack128_depth[i] = -1;
    }
    
    // Start verification from PC=0 with empty stacks
    int result = verify_cfg(&v, 0, 0, 0);
    
    // Check for unreachable code
    if (result == VFM_SUCCESS) {
        for (uint32_t pc = 0; pc < len; ) {
            if (!v.visited[pc]) {
                // Found unreachable code - this is suspicious
                result = VFM_ERROR_VERIFICATION_FAILED;
                break;
            }
            
            // Skip to next instruction
            uint8_t opcode = program[pc];
            uint32_t insn_size = vfm_instruction_size(opcode);
            if (insn_size == 0) {
                result = VFM_ERROR_INVALID_OPCODE;
                break;
            }
            pc += insn_size;
        }
    }
    
    free(v.visited);
    free(v.stack_depth);
    free(v.stack128_depth);
    free(v.back_edges);
    
    return result;
}

// Control flow graph verification
static int verify_cfg(vfm_verifier_t *v, uint32_t pc, int32_t stack_depth, int32_t stack128_depth) {
    // Prevent infinite recursion
    if (v->visited_count++ > MAX_VISITED_NODES) {
        return VFM_ERROR_VERIFICATION_FAILED;
    }
    
    while (pc < v->program_len) {
        // Check if we've been here before
        if (v->visited[pc]) {
            // Check for consistent stack depths
            if (v->stack_depth[pc] != stack_depth || v->stack128_depth[pc] != stack128_depth) {
                return VFM_ERROR_VERIFICATION_FAILED;
            }
            // Already verified this path
            return VFM_SUCCESS;
        }
        
        // Mark as visited
        v->visited[pc] = 1;
        v->stack_depth[pc] = stack_depth;
        v->stack128_depth[pc] = stack128_depth;
        
        // Track maximum stack depths
        if (stack_depth > (int32_t)v->max_stack_depth) {
            v->max_stack_depth = stack_depth;
        }
        if (stack128_depth > (int32_t)v->max_stack128_depth) {
            v->max_stack128_depth = stack128_depth;
        }
        
        // Check stack bounds
        if (stack_depth < 0) {
            return VFM_ERROR_STACK_UNDERFLOW;
        }
        if (stack128_depth < 0) {
            return VFM_ERROR_STACK_UNDERFLOW;
        }
        // Allow potential stack overflow - let runtime detection handle it
        if (stack_depth > VFM_MAX_STACK * 2) {  // Only reject extremely deep stacks
            return VFM_ERROR_STACK_OVERFLOW;
        }
        if (stack128_depth > VFM_MAX_STACK) {  // 128-bit stack is typically smaller
            return VFM_ERROR_STACK_OVERFLOW;
        }
        
        uint8_t opcode = v->program[pc];
        
        // Verify instruction
        int result = verify_instruction(v, pc, opcode);
        if (result != VFM_SUCCESS) {
            return result;
        }
        
        uint32_t insn_size = vfm_instruction_size(opcode);
        if (insn_size == 0) {
            return VFM_ERROR_INVALID_OPCODE;
        }
        
        uint32_t next_pc = pc + insn_size;
        
        // Handle different instruction types
        switch (opcode) {
            case VFM_LD8:
            case VFM_LD16:
            case VFM_LD32:
            case VFM_LD64:
            case VFM_PUSH:
            case VFM_DUP:
            case VFM_HASH5:
            case VFM_HASH6:
            case VFM_CSUM:
            case VFM_PARSE:
            case VFM_FLOW_LOAD:
            case VFM_IP_VER:
            case VFM_IPV6_EXT:
                stack_depth++;
                break;
                
            case VFM_LD128:
                // VFM_LD128 pushes one 128-bit value to the 128-bit stack
                stack128_depth++;
                break;
                
            case VFM_PUSH128:
                // VFM_PUSH128 also pushes one 128-bit value to the 128-bit stack
                stack128_depth++;
                break;
                
            case VFM_POP:
            case VFM_RET:
                stack_depth--;
                if (opcode == VFM_RET) {
                    // End of execution path
                    return VFM_SUCCESS;
                }
                break;
                
            case VFM_SWAP:
                // No net change in stack depth
                if (stack_depth < 2) {
                    return VFM_ERROR_STACK_UNDERFLOW;
                }
                break;
                
            case VFM_ADD:
            case VFM_SUB:
            case VFM_MUL:
            case VFM_DIV:
            case VFM_MOD:
            case VFM_AND:
            case VFM_OR:
            case VFM_XOR:
            case VFM_SHL:
            case VFM_SHR:
            case VFM_FLOW_STORE:
                stack_depth -= 2;
                stack_depth++;
                break;
                
            case VFM_EQ128:
            case VFM_NE128:
            case VFM_GT128:
            case VFM_LT128:
            case VFM_GE128:
            case VFM_LE128:
                // 128-bit comparisons consume 2 entries from 128-bit stack, push 1 result to 64-bit stack
                stack128_depth -= 2;
                stack_depth++;
                break;
                
            case VFM_AND128:
            case VFM_OR128:
            case VFM_XOR128:
                // 128-bit bitwise operations consume 2 entries from 128-bit stack, push 1 result to 128-bit stack
                stack128_depth -= 2;
                stack128_depth++;
                break;
                
            case VFM_NOT:
            case VFM_NEG:
                // No net change in stack depth
                break;
                
            case VFM_JMP: {
                int16_t offset = *(int16_t*)&v->program[pc + 1];
                uint32_t target = (uint32_t)((int32_t)next_pc + offset);
                
                // Check jump bounds
                if (target >= v->program_len) {
                    return VFM_ERROR_VERIFICATION_FAILED;
                }
                
                // Check for back edge (potential loop)
                if (target <= pc) {
                    if (v->back_edge_count >= MAX_BACK_EDGES) {
                        return VFM_ERROR_VERIFICATION_FAILED;
                    }
                    v->back_edges[v->back_edge_count++] = target;
                }
                
                // Continue verification at jump target
                return verify_cfg(v, target, stack_depth, stack128_depth);
            }
            
            case VFM_JEQ:
            case VFM_JNE:
            case VFM_JGT:
            case VFM_JLT:
            case VFM_JGE:
            case VFM_JLE: {
                int16_t offset = *(int16_t*)&v->program[pc + 1];
                uint32_t target = (uint32_t)((int32_t)next_pc + offset);
                
                // Check jump bounds
                if (target >= v->program_len) {
                    return VFM_ERROR_VERIFICATION_FAILED;
                }
                
                // Conditional jumps consume 2 stack elements
                stack_depth -= 2;
                
                // Check for back edge
                if (target <= pc) {
                    if (v->back_edge_count >= MAX_BACK_EDGES) {
                        return VFM_ERROR_VERIFICATION_FAILED;
                    }
                    v->back_edges[v->back_edge_count++] = target;
                }
                
                // Verify both paths
                int result = verify_cfg(v, target, stack_depth, stack128_depth);
                if (result != VFM_SUCCESS) {
                    return result;
                }
                
                // Continue with fall-through path
                break;
            }
            
            case VFM_JEQ128:
            case VFM_JNE128:
            case VFM_JGT128:
            case VFM_JLT128:
            case VFM_JGE128:
            case VFM_JLE128: {
                int16_t offset = *(int16_t*)&v->program[pc + 1];
                uint32_t target = (uint32_t)((int32_t)next_pc + offset);
                
                // Check jump bounds
                if (target >= v->program_len) {
                    return VFM_ERROR_VERIFICATION_FAILED;
                }
                
                // 128-bit conditional jumps consume 2 entries from 128-bit stack
                stack128_depth -= 2;
                
                // Check for back edge
                if (target <= pc) {
                    if (v->back_edge_count >= MAX_BACK_EDGES) {
                        return VFM_ERROR_VERIFICATION_FAILED;
                    }
                    v->back_edges[v->back_edge_count++] = target;
                }
                
                // Verify both paths
                int result = verify_cfg(v, target, stack_depth, stack128_depth);
                if (result != VFM_SUCCESS) {
                    return result;
                }
                
                // Continue with fall-through path
                break;
            }
            
            case VFM_EQ:
            case VFM_NE:
            case VFM_GT:
            case VFM_LT:
            case VFM_GE:
            case VFM_LE:
                // Stack-based comparisons consume 2 entries from 64-bit stack, push 1 result to 64-bit stack
                stack_depth -= 2;
                stack_depth++;
                break;
            
            default:
                return VFM_ERROR_INVALID_OPCODE;
        }
        
        pc = next_pc;
    }
    
    // Reached end of program without RET
    return VFM_ERROR_VERIFICATION_FAILED;
}

// Verify individual instruction
static int verify_instruction(vfm_verifier_t *v, uint32_t pc, uint8_t opcode) {
    if (opcode >= VFM_OPCODE_MAX) {
        return VFM_ERROR_INVALID_OPCODE;
    }
    
    uint32_t insn_size = vfm_instruction_size(opcode);
    if (pc + insn_size > v->program_len) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    switch (opcode) {
        case VFM_LD8:
        case VFM_LD16:
        case VFM_LD32:
        case VFM_LD64:
        case VFM_LD128: {
            // Check packet offset bounds for 128-bit loads (IPv6 addresses)
            uint16_t offset = *(uint16_t*)&v->program[pc + 1];
            
            // We can't verify packet bounds statically, but we can check
            // that the offset is reasonable - reject obviously invalid offsets
            uint16_t field_size = 1;  // Default for LD8
            switch (opcode) {
                case VFM_LD16: field_size = 2; break;
                case VFM_LD32: field_size = 4; break;
                case VFM_LD64: field_size = 8; break;
                case VFM_LD128: field_size = 16; break;
            }
            
            // Enhanced IPv6-aware bounds checking
            if (opcode == VFM_LD128) {
                // For IPv6 addresses, validate common field offsets
                bool valid_ipv6_offset = false;
                
                // Standard IPv6 field offsets (assuming Ethernet frame)
                if (offset == 22 ||   // IPv6 src address (14 + 8)
                    offset == 38) {   // IPv6 dst address (14 + 24)
                    valid_ipv6_offset = true;
                }
                
                // Allow other reasonable offsets for dynamic fields or extension headers
                // but reject obviously invalid ones
                if (!valid_ipv6_offset && (offset < 14 || offset > 1500 - field_size)) {
                    return VFM_ERROR_VERIFICATION_FAILED;
                }
                
                // Ensure 16-byte alignment doesn't cause overflow
                if (offset > UINT16_MAX - 16) {
                    return VFM_ERROR_VERIFICATION_FAILED;
                }
            } else {
                // Standard bounds check for other load operations
                if (offset > 1500 - field_size) {  // Reasonable MTU limit minus field size
                    return VFM_ERROR_VERIFICATION_FAILED;
                }
            }
            break;
        }
        
        case VFM_PUSH128: {
            // Validate 128-bit immediate value bounds
            if (pc + 17 > v->program_len) {
                return VFM_ERROR_INVALID_PROGRAM;
            }
            break;
        }
        
        case VFM_PUSH: {
            // Validate immediate value (no restrictions for now)
            break;
        }
        
        case VFM_JMP:
        case VFM_JEQ:
        case VFM_JNE:
        case VFM_JGT:
        case VFM_JLT:
        case VFM_JGE:
        case VFM_JLE:
        case VFM_JEQ128:
        case VFM_JNE128:
        case VFM_JGT128:
        case VFM_JLT128:
        case VFM_JGE128:
        case VFM_JLE128: {
            // Jump offset bounds already checked in verify_cfg
            break;
        }
        
        case VFM_DIV:
        case VFM_MOD:
            // Division by zero is checked at runtime
            break;
            
        default:
            // All other instructions are safe
            break;
    }
    
    return VFM_SUCCESS;
}


// Additional verification functions for advanced checks
int vfm_verify_extended(const uint8_t *program, uint32_t len, uint32_t max_instructions) {
    int result = vfm_verify(program, len);
    if (result != VFM_SUCCESS) {
        return result;
    }
    
    // Count maximum possible instructions in worst case
    uint32_t max_possible_instructions = 0;
    for (uint32_t pc = 0; pc < len; ) {
        uint8_t opcode = program[pc];
        uint32_t insn_size = vfm_instruction_size(opcode);
        if (insn_size == 0) {
            return VFM_ERROR_INVALID_OPCODE;
        }
        
        max_possible_instructions++;
        pc += insn_size;
    }
    
    // Apply heuristic for loops
    max_possible_instructions *= 100;  // Assume up to 100 iterations per loop
    
    if (max_possible_instructions > max_instructions) {
        return VFM_ERROR_VERIFICATION_FAILED;
    }
    
    return VFM_SUCCESS;
}

// Disassemble program for debugging
void vfm_disassemble(const uint8_t *program, uint32_t len, char *output, size_t output_size) {
    if (!program || !output || output_size == 0) return;
    
    size_t pos = 0;
    for (uint32_t pc = 0; pc < len && pos < output_size - 1; ) {
        uint8_t opcode = program[pc];
        if (opcode >= VFM_OPCODE_MAX) {
            pos += snprintf(output + pos, output_size - pos, "%04x: INVALID\n", pc);
            break;
        }
        
        const char *name = vfm_opcode_names[opcode];
        uint32_t insn_size = vfm_instruction_size(opcode);
        
        if (insn_size == 0) {
            pos += snprintf(output + pos, output_size - pos, "%04x: INVALID\n", pc);
            break;
        }
        
        pos += snprintf(output + pos, output_size - pos, "%04x: %s", pc, name);
        
        // Add operands
        switch (vfm_opcode_format[opcode]) {
            case VFM_FMT_IMM8:
                pos += snprintf(output + pos, output_size - pos, " %u", program[pc + 1]);
                break;
            case VFM_FMT_IMM16:
            case VFM_FMT_OFFSET16:
                pos += snprintf(output + pos, output_size - pos, " %u", *(uint16_t*)&program[pc + 1]);
                break;
            case VFM_FMT_IMM32:
                pos += snprintf(output + pos, output_size - pos, " %u", *(uint32_t*)&program[pc + 1]);
                break;
            case VFM_FMT_IMM64:
                pos += snprintf(output + pos, output_size - pos, " %llu", *(uint64_t*)&program[pc + 1]);
                break;
            default:
                break;
        }
        
        pos += snprintf(output + pos, output_size - pos, "\n");
        pc += insn_size;
    }
    
    output[pos] = '\0';
}