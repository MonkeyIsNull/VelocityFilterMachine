#include "vflisp_types.h"
#include "../../include/vfm.h"  // For opcodes and vfm_verify()
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Forward declarations
static int vfl_compile_node(vfl_node_t *node, vfl_compile_ctx_t *ctx);
static int vfl_emit_opcode(vfl_compile_ctx_t *ctx, uint8_t opcode);
static int vfl_emit_u16(vfl_compile_ctx_t *ctx, uint16_t value);
static int vfl_emit_u64(vfl_compile_ctx_t *ctx, uint64_t value);

// Compilation context management
vfl_compile_ctx_t* vfl_compile_ctx_create(void) {
    vfl_compile_ctx_t *ctx = calloc(1, sizeof(vfl_compile_ctx_t));
    if (!ctx) return NULL;
    
    ctx->bytecode_capacity = 1024;
    ctx->bytecode = malloc(ctx->bytecode_capacity);
    if (!ctx->bytecode) {
        free(ctx);
        return NULL;
    }
    
    return ctx;
}

void vfl_compile_ctx_destroy(vfl_compile_ctx_t *ctx) {
    if (ctx) {
        free(ctx->bytecode);
        free(ctx);
    }
}

// Bytecode emission functions
static int vfl_ensure_capacity(vfl_compile_ctx_t *ctx, uint32_t needed) {
    if (ctx->bytecode_pos + needed > ctx->bytecode_capacity) {
        uint32_t new_capacity = ctx->bytecode_capacity * 2;
        while (new_capacity < ctx->bytecode_pos + needed) {
            new_capacity *= 2;
        }
        
        uint8_t *new_bytecode = realloc(ctx->bytecode, new_capacity);
        if (!new_bytecode) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Memory allocation failed");
            return -1;
        }
        
        ctx->bytecode = new_bytecode;
        ctx->bytecode_capacity = new_capacity;
    }
    return 0;
}

static int vfl_emit_opcode(vfl_compile_ctx_t *ctx, uint8_t opcode) {
    if (vfl_ensure_capacity(ctx, 1) < 0) return -1;
    ctx->bytecode[ctx->bytecode_pos++] = opcode;
    return 0;
}

static int vfl_emit_u8(vfl_compile_ctx_t *ctx, uint8_t value) {
    if (vfl_ensure_capacity(ctx, 1) < 0) return -1;
    ctx->bytecode[ctx->bytecode_pos++] = value;
    return 0;
}

static int vfl_emit_u16(vfl_compile_ctx_t *ctx, uint16_t value) {
    if (vfl_ensure_capacity(ctx, 2) < 0) return -1;
    ctx->bytecode[ctx->bytecode_pos++] = value & 0xFF;
    ctx->bytecode[ctx->bytecode_pos++] = (value >> 8) & 0xFF;
    return 0;
}

static int vfl_emit_u64(vfl_compile_ctx_t *ctx, uint64_t value) {
    if (vfl_ensure_capacity(ctx, 8) < 0) return -1;
    for (int i = 0; i < 8; i++) {
        ctx->bytecode[ctx->bytecode_pos++] = (value >> (i * 8)) & 0xFF;
    }
    return 0;
}


// Stack management
static int vfl_push_stack(vfl_compile_ctx_t *ctx) {
    ctx->stack_depth++;
    if (ctx->stack_depth > ctx->max_stack_depth) {
        ctx->max_stack_depth = ctx->stack_depth;
    }
    if (ctx->stack_depth > 256) {  // VFM_MAX_STACK
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Stack overflow (max %d)", 256);
        return -1;
    }
    return 0;
}

static int vfl_pop_stack(vfl_compile_ctx_t *ctx) {
    if (ctx->stack_depth == 0) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Stack underflow");
        return -1;
    }
    ctx->stack_depth--;
    return 0;
}

// Compile packet field access with IPv6 support
static int vfl_compile_field(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    const vfl_field_info_t *info = node->data.field.field_info;
    
    // Handle special IP version field
    if (info->type == VFL_FIELD_IP_VERSION) {
        // Use VFM_IP_VER opcode to get IP version (4 or 6)
        if (vfl_emit_opcode(ctx, VFM_IP_VER) < 0) return -1;
        return vfl_push_stack(ctx);
    }
    
    // Handle special IPv6 fields
    if (info->type == VFL_FIELD_SRC_IP6 || info->type == VFL_FIELD_DST_IP6) {
        // Use VFM_LD128 opcode for proper 128-bit IPv6 address loading
        
        uint16_t offset;
        switch (info->type) {
            case VFL_FIELD_SRC_IP6:
                // IPv6 source address at offset 22 (14 + 8)
                offset = 22;
                break;
                
            case VFL_FIELD_DST_IP6:
                // IPv6 destination address at offset 38 (14 + 24)
                offset = 38;
                break;
                
            default:
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unknown IPv6 field type %d", info->type);
                return -1;
        }
        
        // Emit VFM_LD128 opcode with offset
        if (vfl_emit_opcode(ctx, VFM_LD128) < 0) return -1;
        if (vfl_emit_u16(ctx, offset) < 0) return -1;
        
        // VFM_LD128 pushes high and low 64-bit values to stack
        if (vfl_push_stack(ctx) < 0) return -1;  // High from LD128
        return vfl_push_stack(ctx);              // Low from LD128
    } else if (info->type >= VFL_FIELD_HAS_EXT_HDR && info->type <= VFL_FIELD_FRAG_FLAGS) {
        // IPv6 extension header fields - use special opcode
        if (vfl_emit_opcode(ctx, VFM_IPV6_EXT) < 0) return -1;
        if (vfl_emit_u8(ctx, (uint8_t)info->type) < 0) return -1;
    } else if (info->type == VFL_FIELD_SRC_PORT || info->type == VFL_FIELD_DST_PORT) {
        // Transport fields may need dynamic offset calculation for IPv6
        // For compile-time, we'll use a special approach that works for both IPv4 and IPv6
        
        // Emit a runtime field extraction opcode that handles dynamic offsets
        if (vfl_emit_opcode(ctx, VFM_IPV6_EXT) < 0) return -1;
        if (vfl_emit_u8(ctx, (uint8_t)info->type) < 0) return -1;
    } else {
        // Static offset fields (IPv4 and common fields)
        // Emit appropriate load instruction based on field size
        switch (info->size) {
            case 1:
                if (vfl_emit_opcode(ctx, VFM_LD8) < 0) return -1;
                break;
            case 2:
                if (vfl_emit_opcode(ctx, VFM_LD16) < 0) return -1;
                break;
            case 4:
                if (vfl_emit_opcode(ctx, VFM_LD32) < 0) return -1;
                break;
            case 16:
                // 16-byte fields (IPv6) use two 64-bit loads for now
                // This is handled in the dynamic offset section above
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "16-byte static fields not supported in legacy mode");
                return -1;
            default:
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unsupported field size: %d", info->size);
                return -1;
        }
        
        // Emit offset
        if (vfl_emit_u16(ctx, info->offset) < 0) return -1;
    }
    
    // Field access pushes values onto stack
    // IPv6 fields push two values (using two LD64 operations)
    // Regular fields push one value
    if (info->size == 16 && info->offset_calc != NULL && info->offset == 0) {
        // IPv6 fields push two 64-bit values
        if (vfl_push_stack(ctx) < 0) return -1;  // First 64-bit value
        return vfl_push_stack(ctx);              // Second 64-bit value
    } else {
        // Regular fields push one value
        return vfl_push_stack(ctx);
    }
}

// Compile integer literal
static int vfl_compile_integer(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, (uint64_t)node->data.integer) < 0) return -1;
    return vfl_push_stack(ctx);
}

// Compile IPv6 address literal
static int vfl_compile_ipv6(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    // Convert IPv6 address to two 64-bit values (high and low)
    uint64_t high = 0, low = 0;
    for (int i = 0; i < 8; i++) {
        high = (high << 8) | node->data.ipv6[i];
    }
    for (int i = 8; i < 16; i++) {
        low = (low << 8) | node->data.ipv6[i];
    }
    
    // Push high 64 bits first
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, high) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Push low 64 bits second
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, low) < 0) return -1;
    return vfl_push_stack(ctx);
}

// Compile binary arithmetic operation
static int vfl_compile_binary_op(vfl_node_t *node, vfl_compile_ctx_t *ctx, uint8_t opcode) {
    if (node->data.list.count < 2) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Binary operation requires at least 2 arguments");
        return -1;
    }
    
    // Compile first argument
    if (vfl_compile_node(node->data.list.children[1], ctx) < 0) return -1;
    
    // Compile remaining arguments and emit operations
    for (int i = 2; i < node->data.list.count; i++) {
        if (vfl_compile_node(node->data.list.children[i], ctx) < 0) return -1;
        if (vfl_emit_opcode(ctx, opcode) < 0) return -1;
        if (vfl_pop_stack(ctx) < 0) return -1;  // Pop two, push one
    }
    
    return 0;
}

// Check if operands are IPv6 (128-bit) based on field types
static bool vfl_is_ipv6_comparison(vfl_node_t *left, vfl_node_t *right) {
    // Check if either operand is an IPv6 field
    if (left->type == VFL_NODE_FIELD) {
        vfl_field_type_t field_type = left->data.field.field_type;
        if (field_type == VFL_FIELD_SRC_IP6 || field_type == VFL_FIELD_DST_IP6) {
            return true;
        }
    }
    if (right->type == VFL_NODE_FIELD) {
        vfl_field_type_t field_type = right->data.field.field_type;
        if (field_type == VFL_FIELD_SRC_IP6 || field_type == VFL_FIELD_DST_IP6) {
            return true;
        }
    }
    
    // Check if either operand is an IPv6 literal
    if (left->type == VFL_NODE_IPV6 || right->type == VFL_NODE_IPV6) {
        return true;
    }
    
    return false;
}

// Compile comparison operation - generates clean control flow pattern
static int vfl_compile_comparison(vfl_node_t *node, vfl_compile_ctx_t *ctx, uint8_t jump_opcode) {
    if (node->data.list.count != 3) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Comparison requires exactly 2 arguments");
        return -1;
    }
    
    vfl_node_t *left = node->data.list.children[1];
    vfl_node_t *right = node->data.list.children[2];
    
    // Determine if this is an IPv6 (128-bit) comparison
    bool is_ipv6 = vfl_is_ipv6_comparison(left, right);
    
    // Compile both arguments onto stack
    if (vfl_compile_node(left, ctx) < 0) return -1;
    if (vfl_compile_node(right, ctx) < 0) return -1;
    
    // Use appropriate comparison instruction based on operand type
    uint8_t comparison_opcode;
    if (is_ipv6) {
        // Use 128-bit comparison opcodes for IPv6
        switch (jump_opcode) {
            case VFM_JEQ: comparison_opcode = VFM_EQ128; break;
            case VFM_JNE: comparison_opcode = VFM_NE128; break;
            case VFM_JGT: comparison_opcode = VFM_GT128; break;
            case VFM_JLT: comparison_opcode = VFM_LT128; break;
            case VFM_JGE: comparison_opcode = VFM_GE128; break;
            case VFM_JLE: comparison_opcode = VFM_LE128; break;
            default:
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unsupported IPv6 comparison opcode: %d", jump_opcode);
                return -1;
        }
        
        // Emit 128-bit comparison and adjust stack
        if (vfl_emit_opcode(ctx, comparison_opcode) < 0) return -1;
        
        // 128-bit comparison consumes 4 stack entries (2 IPv6 addresses) and produces 1 result
        if (vfl_pop_stack(ctx) < 0) return -1;  // Right operand low
        if (vfl_pop_stack(ctx) < 0) return -1;  // Right operand high  
        if (vfl_pop_stack(ctx) < 0) return -1;  // Left operand low
        if (vfl_pop_stack(ctx) < 0) return -1;  // Left operand high
        if (vfl_push_stack(ctx) < 0) return -1; // Comparison result
        
        return 0;
    }
    
    // Use standard comparison instruction
    comparison_opcode = jump_opcode;
    
    // Use VFM's native comparison with clean control flow
    // Jump to true branch if comparison succeeds
    if (vfl_emit_opcode(ctx, comparison_opcode) < 0) return -1;
    uint32_t true_jump_pos = ctx->bytecode_pos;
    if (vfl_emit_u16(ctx, 0) < 0) return -1;  // Will be patched
    
    // The jump instruction consumes operands from stack at runtime
    // For stack tracking purposes, all comparisons consume 2 logical values
    // regardless of whether they're IPv4 (64-bit) or IPv6 (128-bit)
    if (vfl_pop_stack(ctx) < 0) return -1;  // Right operand
    if (vfl_pop_stack(ctx) < 0) return -1;  // Left operand
    
    // False branch: push 0 and jump to end
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 0) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    if (vfl_emit_opcode(ctx, VFM_JMP) < 0) return -1;
    uint32_t end_jump_pos = ctx->bytecode_pos;
    if (vfl_emit_u16(ctx, 0) < 0) return -1;  // Will be patched
    
    // Patch true branch jump offset
    uint16_t true_offset = ctx->bytecode_pos - true_jump_pos - 2;
    ctx->bytecode[true_jump_pos] = true_offset & 0xFF;
    ctx->bytecode[true_jump_pos + 1] = (true_offset >> 8) & 0xFF;
    
    // True branch: push 1 (stack balance with false branch)
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 1) < 0) return -1;
    // Don't increment stack here since false branch already did
    
    // Patch end jump offset
    uint16_t end_offset = ctx->bytecode_pos - end_jump_pos - 2;
    ctx->bytecode[end_jump_pos] = end_offset & 0xFF;
    ctx->bytecode[end_jump_pos + 1] = (end_offset >> 8) & 0xFF;
    
    return 0;
}

// Compile logical AND
static int vfl_compile_and(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    if (node->data.list.count < 2) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "AND requires at least 1 argument");
        return -1;
    }
    
    // Start with first argument
    if (vfl_compile_node(node->data.list.children[1], ctx) < 0) return -1;
    
    // For each additional argument, short-circuit if false
    for (int i = 2; i < node->data.list.count; i++) {
        // Duplicate current result
        if (vfl_emit_opcode(ctx, VFM_DUP) < 0) return -1;
        if (vfl_push_stack(ctx) < 0) return -1;
        
        // If false, jump to end
        if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
        if (vfl_emit_u64(ctx, 0) < 0) return -1;
        if (vfl_push_stack(ctx) < 0) return -1;
        
        if (vfl_emit_opcode(ctx, VFM_JEQ) < 0) return -1;
        uint32_t jump_pos = ctx->bytecode_pos;
        if (vfl_emit_u16(ctx, 0) < 0) return -1;  // Will be patched
        
        if (vfl_pop_stack(ctx) < 0) return -1;  // Pop comparison operands
        if (vfl_pop_stack(ctx) < 0) return -1;
        
        // Pop the duplicated result and compile next argument
        if (vfl_emit_opcode(ctx, VFM_POP) < 0) return -1;
        if (vfl_pop_stack(ctx) < 0) return -1;
        
        if (vfl_compile_node(node->data.list.children[i], ctx) < 0) return -1;
        
        // Patch jump offset
        uint16_t offset = ctx->bytecode_pos - jump_pos - 2;
        ctx->bytecode[jump_pos] = offset & 0xFF;
        ctx->bytecode[jump_pos + 1] = (offset >> 8) & 0xFF;
    }
    
    return 0;
}

// Compile logical OR
static int vfl_compile_or(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    if (node->data.list.count < 2) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "OR requires at least 1 argument");
        return -1;
    }
    
    // Start with first argument
    if (vfl_compile_node(node->data.list.children[1], ctx) < 0) return -1;
    
    // For each additional argument, short-circuit if true
    for (int i = 2; i < node->data.list.count; i++) {
        // Duplicate current result
        if (vfl_emit_opcode(ctx, VFM_DUP) < 0) return -1;
        if (vfl_push_stack(ctx) < 0) return -1;
        
        // If true, jump to end
        if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
        if (vfl_emit_u64(ctx, 1) < 0) return -1;
        if (vfl_push_stack(ctx) < 0) return -1;
        
        if (vfl_emit_opcode(ctx, VFM_JEQ) < 0) return -1;
        uint32_t jump_pos = ctx->bytecode_pos;
        if (vfl_emit_u16(ctx, 0) < 0) return -1;  // Will be patched
        
        if (vfl_pop_stack(ctx) < 0) return -1;  // Pop comparison operands
        if (vfl_pop_stack(ctx) < 0) return -1;
        
        // Pop the duplicated result and compile next argument
        if (vfl_emit_opcode(ctx, VFM_POP) < 0) return -1;
        if (vfl_pop_stack(ctx) < 0) return -1;
        
        if (vfl_compile_node(node->data.list.children[i], ctx) < 0) return -1;
        
        // Patch jump offset
        uint16_t offset = ctx->bytecode_pos - jump_pos - 2;
        ctx->bytecode[jump_pos] = offset & 0xFF;
        ctx->bytecode[jump_pos + 1] = (offset >> 8) & 0xFF;
    }
    
    return 0;
}

// Compile logical NOT
static int vfl_compile_not(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    if (node->data.list.count != 2) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "NOT requires exactly 1 argument");
        return -1;
    }
    
    // Compile argument
    if (vfl_compile_node(node->data.list.children[1], ctx) < 0) return -1;
    
    // Compare with 0 to test if false
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 0) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Jump to true branch if argument equals 0 (meaning NOT should return 1)
    if (vfl_emit_opcode(ctx, VFM_JEQ) < 0) return -1;
    uint32_t true_jump_pos = ctx->bytecode_pos;
    if (vfl_emit_u16(ctx, 0) < 0) return -1;  // Will be patched
    
    // Comparison consumed both operands from stack
    if (vfl_pop_stack(ctx) < 0) return -1;
    if (vfl_pop_stack(ctx) < 0) return -1;
    
    // False branch: argument was non-zero, so NOT returns 0
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 0) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Jump over true branch
    if (vfl_emit_opcode(ctx, VFM_JMP) < 0) return -1;
    uint32_t end_jump_pos = ctx->bytecode_pos;
    if (vfl_emit_u16(ctx, 0) < 0) return -1;  // Will be patched
    
    // Patch true branch jump offset
    uint16_t true_offset = ctx->bytecode_pos - true_jump_pos - 2;
    ctx->bytecode[true_jump_pos] = true_offset & 0xFF;
    ctx->bytecode[true_jump_pos + 1] = (true_offset >> 8) & 0xFF;
    
    // True branch: argument was zero, so NOT returns 1
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 1) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Patch end jump offset
    uint16_t end_offset = ctx->bytecode_pos - end_jump_pos - 2;
    ctx->bytecode[end_jump_pos] = end_offset & 0xFF;
    ctx->bytecode[end_jump_pos + 1] = (end_offset >> 8) & 0xFF;
    
    return 0;
}

// Compile IF expression
static int vfl_compile_if(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    if (node->data.list.count != 4) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "IF requires exactly 3 arguments: condition, then, else");
        return -1;
    }
    
    // Compile condition
    if (vfl_compile_node(node->data.list.children[1], ctx) < 0) return -1;
    
    // Test condition
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 0) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Jump to else clause if condition is false
    if (vfl_emit_opcode(ctx, VFM_JEQ) < 0) return -1;
    uint32_t else_jump_pos = ctx->bytecode_pos;
    if (vfl_emit_u16(ctx, 0) < 0) return -1;  // Will be patched
    
    if (vfl_pop_stack(ctx) < 0) return -1;  // Pop comparison operands
    if (vfl_pop_stack(ctx) < 0) return -1;
    
    // Compile then clause
    if (vfl_compile_node(node->data.list.children[2], ctx) < 0) return -1;
    
    // Jump over else clause
    if (vfl_emit_opcode(ctx, VFM_JMP) < 0) return -1;
    uint32_t end_jump_pos = ctx->bytecode_pos;
    if (vfl_emit_u16(ctx, 0) < 0) return -1;  // Will be patched
    
    // Patch else jump
    uint16_t else_offset = ctx->bytecode_pos - else_jump_pos - 2;
    ctx->bytecode[else_jump_pos] = else_offset & 0xFF;
    ctx->bytecode[else_jump_pos + 1] = (else_offset >> 8) & 0xFF;
    
    // Compile else clause
    if (vfl_compile_node(node->data.list.children[3], ctx) < 0) return -1;
    
    // Patch end jump
    uint16_t end_offset = ctx->bytecode_pos - end_jump_pos - 2;
    ctx->bytecode[end_jump_pos] = end_offset & 0xFF;
    ctx->bytecode[end_jump_pos + 1] = (end_offset >> 8) & 0xFF;
    
    return 0;
}

// Compile function call
static int vfl_compile_function(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    if (node->data.list.count < 1) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Empty function call");
        return -1;
    }
    
    vfl_node_t *func_node = node->data.list.children[0];
    if (func_node->type != VFL_NODE_SYMBOL) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Function name must be a symbol");
        return -1;
    }
    
    vfl_func_type_t func_type = func_node->data.symbol.func_type;
    if (func_type >= VFL_FUNC_MAX) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unknown function: %s", func_node->data.symbol.name);
        return -1;
    }
    
    // Validate argument count
    const vfl_func_info_t *info = &vfl_func_info[func_type];
    int arg_count = node->data.list.count - 1;  // Exclude function name
    
    if (arg_count < info->min_args || (info->max_args != -1 && arg_count > info->max_args)) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Function %s expects %d-%d arguments, got %d",
                 info->name, info->min_args, info->max_args == -1 ? 999 : info->max_args, arg_count);
        return -1;
    }
    
    // Compile function
    switch (func_type) {
        case VFL_FUNC_IF:
            return vfl_compile_if(node, ctx);
        case VFL_FUNC_AND:
            return vfl_compile_and(node, ctx);
        case VFL_FUNC_OR:
            return vfl_compile_or(node, ctx);
        case VFL_FUNC_NOT:
            return vfl_compile_not(node, ctx);
        case VFL_FUNC_EQ:
            return vfl_compile_comparison(node, ctx, VFM_JEQ);
        case VFL_FUNC_NE:
            return vfl_compile_comparison(node, ctx, VFM_JNE);
        case VFL_FUNC_GT:
            return vfl_compile_comparison(node, ctx, VFM_JGT);
        case VFL_FUNC_GE:
            return vfl_compile_comparison(node, ctx, VFM_JGE);
        case VFL_FUNC_LT:
            return vfl_compile_comparison(node, ctx, VFM_JLT);
        case VFL_FUNC_LE:
            return vfl_compile_comparison(node, ctx, VFM_JLE);
        case VFL_FUNC_ADD:
            return vfl_compile_binary_op(node, ctx, VFM_ADD);
        case VFL_FUNC_SUB:
            return vfl_compile_binary_op(node, ctx, VFM_SUB);
        case VFL_FUNC_MUL:
            return vfl_compile_binary_op(node, ctx, VFM_MUL);
        case VFL_FUNC_DIV:
            return vfl_compile_binary_op(node, ctx, VFM_DIV);
        case VFL_FUNC_MOD:
            return vfl_compile_binary_op(node, ctx, VFM_MOD);
        case VFL_FUNC_BAND:
            return vfl_compile_binary_op(node, ctx, VFM_AND);
        case VFL_FUNC_BOR:
            return vfl_compile_binary_op(node, ctx, VFM_OR);
        case VFL_FUNC_BXOR:
            return vfl_compile_binary_op(node, ctx, VFM_XOR);
        case VFL_FUNC_SHL:
            return vfl_compile_binary_op(node, ctx, VFM_SHL);
        case VFL_FUNC_SHR:
            return vfl_compile_binary_op(node, ctx, VFM_SHR);
        default:
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Function %s not implemented", info->name);
            return -1;
    }
}

// Main compilation function
static int vfl_compile_node(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    if (!node) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "NULL node");
        return -1;
    }
    
    switch (node->type) {
        case VFL_NODE_INTEGER:
            return vfl_compile_integer(node, ctx);
        case VFL_NODE_IPV6:
            return vfl_compile_ipv6(node, ctx);
        case VFL_NODE_FIELD:
            return vfl_compile_field(node, ctx);
        case VFL_NODE_LIST:
            return vfl_compile_function(node, ctx);
        case VFL_NODE_SYMBOL:
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Bare symbol not allowed: %s", node->data.symbol.name);
            return -1;
        default:
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unknown node type: %d", node->type);
            return -1;
    }
}

// Public API
int vfl_compile(vfl_node_t *ast, uint8_t **bytecode, uint32_t *bytecode_len, char *error_msg, size_t error_msg_size) {
    vfl_compile_ctx_t *ctx = vfl_compile_ctx_create();
    if (!ctx) {
        if (error_msg) snprintf(error_msg, error_msg_size, "Memory allocation failed");
        return -1;
    }
    
    // Compile the AST
    int result = vfl_compile_node(ast, ctx);
    if (result < 0) {
        if (error_msg) snprintf(error_msg, error_msg_size, "%s", ctx->error_msg);
        vfl_compile_ctx_destroy(ctx);
        return -1;
    }
    
    // Check final stack state - handle IPv6 case where 2 values might be left
    if (ctx->stack_depth == 2) {
        // Likely an IPv6 value at top level - drop the low part for boolean context
        if (vfl_emit_opcode(ctx, VFM_POP) < 0) {
            if (error_msg) snprintf(error_msg, error_msg_size, "Failed to emit POP for IPv6 boolean context");
            vfl_compile_ctx_destroy(ctx);
            return -1;
        }
        ctx->stack_depth--;
    }
    
    // Emit return instruction
    if (vfl_emit_opcode(ctx, VFM_RET) < 0) {
        if (error_msg) snprintf(error_msg, error_msg_size, "Failed to emit return instruction");
        vfl_compile_ctx_destroy(ctx);
        return -1;
    }
    
    if (ctx->stack_depth != 1) {
        if (error_msg) snprintf(error_msg, error_msg_size, "Stack imbalance: expected 1, got %d", ctx->stack_depth);
        vfl_compile_ctx_destroy(ctx);
        return -1;
    }
    
    // Verify generated bytecode
    int verify_result = vfm_verify(ctx->bytecode, ctx->bytecode_pos);
    if (verify_result < 0) {
        if (error_msg) snprintf(error_msg, error_msg_size, "Bytecode verification failed: code %d", verify_result);
        vfl_compile_ctx_destroy(ctx);
        return -1;
    }
    
    // Return bytecode
    *bytecode = ctx->bytecode;
    *bytecode_len = ctx->bytecode_pos;
    
    // Don't destroy bytecode, transfer ownership
    ctx->bytecode = NULL;
    vfl_compile_ctx_destroy(ctx);
    
    return 0;
}

// Compile from string
int vfl_compile_string(const char *source, uint8_t **bytecode, uint32_t *bytecode_len, char *error_msg, size_t error_msg_size) {
    vfl_node_t *ast = vfl_parse(source);
    if (!ast) {
        if (error_msg) snprintf(error_msg, error_msg_size, "Parse error");
        return -1;
    }
    
    int result = vfl_compile(ast, bytecode, bytecode_len, error_msg, error_msg_size);
    vfl_node_destroy(ast);
    return result;
}

// Compile from file
int vfl_compile_file(const char *filename, uint8_t **bytecode, uint32_t *bytecode_len, char *error_msg, size_t error_msg_size) {
    vfl_node_t *ast = vfl_parse_file(filename);
    if (!ast) {
        if (error_msg) snprintf(error_msg, error_msg_size, "Failed to parse file: %s", filename);
        return -1;
    }
    
    int result = vfl_compile(ast, bytecode, bytecode_len, error_msg, error_msg_size);
    vfl_node_destroy(ast);
    return result;
}

// Function prototypes for parser (implemented in vflisp_parser.c)
extern vfl_node_t* vfl_parse(const char *input);
extern vfl_node_t* vfl_parse_file(const char *filename);