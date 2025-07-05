#include "vflisp_types.h"
#include "../../src/opcodes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

// Forward declarations
static int vfl_compile_node(vfl_node_t *node, vfl_compile_ctx_t *ctx);
static int vfl_emit_opcode(vfl_compile_ctx_t *ctx, uint8_t opcode);
static int vfl_emit_u16(vfl_compile_ctx_t *ctx, uint16_t value);
static int vfl_emit_u32(vfl_compile_ctx_t *ctx, uint32_t value);
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

static int vfl_emit_u16(vfl_compile_ctx_t *ctx, uint16_t value) {
    if (vfl_ensure_capacity(ctx, 2) < 0) return -1;
    ctx->bytecode[ctx->bytecode_pos++] = value & 0xFF;
    ctx->bytecode[ctx->bytecode_pos++] = (value >> 8) & 0xFF;
    return 0;
}

static int vfl_emit_u32(vfl_compile_ctx_t *ctx, uint32_t value) {
    if (vfl_ensure_capacity(ctx, 4) < 0) return -1;
    ctx->bytecode[ctx->bytecode_pos++] = value & 0xFF;
    ctx->bytecode[ctx->bytecode_pos++] = (value >> 8) & 0xFF;
    ctx->bytecode[ctx->bytecode_pos++] = (value >> 16) & 0xFF;
    ctx->bytecode[ctx->bytecode_pos++] = (value >> 24) & 0xFF;
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

// Compile packet field access
static int vfl_compile_field(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    const vfl_field_info_t *info = node->data.field.field_info;
    
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
        default:
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unsupported field size: %d", info->size);
            return -1;
    }
    
    // Emit offset
    if (vfl_emit_u16(ctx, info->offset) < 0) return -1;
    
    // Field access pushes one value onto stack
    return vfl_push_stack(ctx);
}

// Compile integer literal
static int vfl_compile_integer(vfl_node_t *node, vfl_compile_ctx_t *ctx) {
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, (uint64_t)node->data.integer) < 0) return -1;
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

// Compile comparison operation
static int vfl_compile_comparison(vfl_node_t *node, vfl_compile_ctx_t *ctx, uint8_t jump_opcode) {
    if (node->data.list.count != 3) {
        snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Comparison requires exactly 2 arguments");
        return -1;
    }
    
    // Compile both arguments
    if (vfl_compile_node(node->data.list.children[1], ctx) < 0) return -1;
    if (vfl_compile_node(node->data.list.children[2], ctx) < 0) return -1;
    
    // For equality, use a different approach
    if (jump_opcode == VFM_JEQ) {
        // Compare using subtract and check if result is zero
        if (vfl_emit_opcode(ctx, VFM_SUB) < 0) return -1;
        if (vfl_pop_stack(ctx) < 0) return -1;  // Pop two operands, push one result
        
        // Convert to boolean: if 0 then 1, else 0
        // Duplicate the result for testing
        if (vfl_emit_opcode(ctx, VFM_DUP) < 0) return -1;
        if (vfl_push_stack(ctx) < 0) return -1;
        
        // Test if zero
        if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
        if (vfl_emit_u64(ctx, 0) < 0) return -1;
        if (vfl_push_stack(ctx) < 0) return -1;
        
        // Jump to true branch if equal (difference is 0)
        if (vfl_emit_opcode(ctx, VFM_JEQ) < 0) return -1;
        if (vfl_emit_u16(ctx, 11) < 0) return -1;  // Jump to true branch
        
        // False branch: pop original value and push 0
        if (vfl_pop_stack(ctx) < 0) return -1;  // Pop comparison result
        if (vfl_pop_stack(ctx) < 0) return -1;  // Pop duplicate
        if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
        if (vfl_emit_u64(ctx, 0) < 0) return -1;
        if (vfl_push_stack(ctx) < 0) return -1;
        if (vfl_emit_opcode(ctx, VFM_JMP) < 0) return -1;
        if (vfl_emit_u16(ctx, 10) < 0) return -1;  // Jump over true branch
        
        // True branch: pop duplicate and push 1
        if (vfl_pop_stack(ctx) < 0) return -1;  // Pop comparison result
        if (vfl_pop_stack(ctx) < 0) return -1;  // Pop duplicate
        if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
        if (vfl_emit_u64(ctx, 1) < 0) return -1;
        if (vfl_push_stack(ctx) < 0) return -1;
        
        return 0;
    }
    
    // For other comparisons, use the jump instruction directly
    // Push 1 (true result)
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 1) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Jump over false result if condition is true
    if (vfl_emit_opcode(ctx, jump_opcode) < 0) return -1;
    if (vfl_emit_u16(ctx, 10) < 0) return -1;  // Jump 10 bytes forward
    
    // Pop true result and push false result
    if (vfl_emit_opcode(ctx, VFM_POP) < 0) return -1;
    if (vfl_pop_stack(ctx) < 0) return -1;
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 0) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Pop the two comparison operands
    if (vfl_pop_stack(ctx) < 0) return -1;
    if (vfl_pop_stack(ctx) < 0) return -1;
    
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
    
    // Convert to boolean: if 0 then 1, else 0
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 0) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Push 1 (true result)
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 1) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Jump over false result if condition is equal to 0
    if (vfl_emit_opcode(ctx, VFM_JEQ) < 0) return -1;
    if (vfl_emit_u16(ctx, 10) < 0) return -1;  // Jump 10 bytes forward
    
    // Pop true result and push false result
    if (vfl_emit_opcode(ctx, VFM_POP) < 0) return -1;
    if (vfl_pop_stack(ctx) < 0) return -1;
    if (vfl_emit_opcode(ctx, VFM_PUSH) < 0) return -1;
    if (vfl_emit_u64(ctx, 0) < 0) return -1;
    if (vfl_push_stack(ctx) < 0) return -1;
    
    // Pop the comparison operands
    if (vfl_pop_stack(ctx) < 0) return -1;
    if (vfl_pop_stack(ctx) < 0) return -1;
    
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
    
    // Emit return instruction
    if (vfl_emit_opcode(ctx, VFM_RET) < 0) {
        if (error_msg) snprintf(error_msg, error_msg_size, "Failed to emit return instruction");
        vfl_compile_ctx_destroy(ctx);
        return -1;
    }
    
    // Check final stack state
    if (ctx->stack_depth != 1) {
        if (error_msg) snprintf(error_msg, error_msg_size, "Stack imbalance: expected 1, got %d", ctx->stack_depth);
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