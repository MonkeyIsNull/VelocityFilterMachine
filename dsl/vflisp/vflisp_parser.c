#include "vflisp_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

// Node creation functions
vfl_node_t* vfl_node_create(vfl_node_type_t type) {
    vfl_node_t *node = calloc(1, sizeof(vfl_node_t));
    if (!node) return NULL;
    node->type = type;
    return node;
}

void vfl_node_destroy(vfl_node_t *node) {
    if (!node) return;
    
    switch (node->type) {
        case VFL_NODE_SYMBOL:
            free(node->data.symbol.name);
            break;
        case VFL_NODE_LIST:
            for (int i = 0; i < node->data.list.count; i++) {
                vfl_node_destroy(node->data.list.children[i]);
            }
            free(node->data.list.children);
            break;
        case VFL_NODE_INTEGER:
        case VFL_NODE_FIELD:
        case VFL_NODE_IPV6:
            // No cleanup needed
            break;
    }
    free(node);
}

vfl_node_t* vfl_node_create_integer(int64_t value) {
    vfl_node_t *node = vfl_node_create(VFL_NODE_INTEGER);
    if (!node) return NULL;
    node->data.integer = value;
    return node;
}

vfl_node_t* vfl_node_create_symbol(const char *name) {
    vfl_node_t *node = vfl_node_create(VFL_NODE_SYMBOL);
    if (!node) return NULL;
    node->data.symbol.name = strdup(name);
    if (!node->data.symbol.name) {
        free(node);
        return NULL;
    }
    node->data.symbol.func_type = vfl_lookup_function(name);
    return node;
}

vfl_node_t* vfl_node_create_field(vfl_field_type_t field_type) {
    vfl_node_t *node = vfl_node_create(VFL_NODE_FIELD);
    if (!node) return NULL;
    node->data.field.field_type = field_type;
    node->data.field.field_info = &vfl_field_info[field_type];
    return node;
}

vfl_node_t* vfl_node_create_list(void) {
    vfl_node_t *node = vfl_node_create(VFL_NODE_LIST);
    if (!node) return NULL;
    node->data.list.capacity = 4;
    node->data.list.children = calloc(node->data.list.capacity, sizeof(vfl_node_t*));
    if (!node->data.list.children) {
        free(node);
        return NULL;
    }
    return node;
}

vfl_node_t* vfl_node_create_ipv6(const uint8_t ipv6[16]) {
    vfl_node_t *node = vfl_node_create(VFL_NODE_IPV6);
    if (!node) return NULL;
    memcpy(node->data.ipv6, ipv6, 16);
    return node;
}

void vfl_node_list_append(vfl_node_t *list, vfl_node_t *child) {
    if (list->type != VFL_NODE_LIST) return;
    
    if (list->data.list.count >= list->data.list.capacity) {
        list->data.list.capacity *= 2;
        list->data.list.children = realloc(list->data.list.children, 
                                         list->data.list.capacity * sizeof(vfl_node_t*));
        if (!list->data.list.children) return;
    }
    
    list->data.list.children[list->data.list.count++] = child;
}

// Utility functions
vfl_field_type_t vfl_lookup_field(const char *name) {
    for (int i = 0; i < VFL_FIELD_MAX; i++) {
        if (strcmp(vfl_field_info[i].name, name) == 0) {
            return vfl_field_info[i].type;
        }
    }
    return VFL_FIELD_MAX;  // Not found
}

vfl_func_type_t vfl_lookup_function(const char *name) {
    for (int i = 0; i < VFL_FUNC_MAX; i++) {
        if (strcmp(vfl_func_info[i].name, name) == 0) {
            return vfl_func_info[i].type;
        }
    }
    return VFL_FUNC_MAX;  // Not found
}

const char* vfl_node_type_name(vfl_node_type_t type) {
    switch (type) {
        case VFL_NODE_INTEGER: return "INTEGER";
        case VFL_NODE_SYMBOL: return "SYMBOL";
        case VFL_NODE_LIST: return "LIST";
        case VFL_NODE_FIELD: return "FIELD";
        case VFL_NODE_IPV6: return "IPV6";
        default: return "UNKNOWN";
    }
}

const char* vfl_field_type_name(vfl_field_type_t type) {
    if (type >= VFL_FIELD_MAX) return "UNKNOWN";
    return vfl_field_info[type].name;
}

const char* vfl_func_type_name(vfl_func_type_t type) {
    if (type >= VFL_FUNC_MAX) return "UNKNOWN";
    return vfl_func_info[type].name;
}

// Print AST for debugging
void vfl_node_print(const vfl_node_t *node, int indent) {
    if (!node) return;
    
    for (int i = 0; i < indent; i++) printf("  ");
    
    switch (node->type) {
        case VFL_NODE_INTEGER:
            printf("INTEGER: %lld\n", (long long)node->data.integer);
            break;
        case VFL_NODE_SYMBOL:
            printf("SYMBOL: %s\n", node->data.symbol.name);
            break;
        case VFL_NODE_FIELD:
            printf("FIELD: %s (offset=%d, size=%d)\n",
                   node->data.field.field_info->name,
                   node->data.field.field_info->offset,
                   node->data.field.field_info->size);
            break;
        case VFL_NODE_LIST:
            printf("LIST: (%d children)\n", node->data.list.count);
            for (int i = 0; i < node->data.list.count; i++) {
                vfl_node_print(node->data.list.children[i], indent + 1);
            }
            break;
        case VFL_NODE_IPV6:
            printf("IPV6: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                   node->data.ipv6[0], node->data.ipv6[1], node->data.ipv6[2], node->data.ipv6[3],
                   node->data.ipv6[4], node->data.ipv6[5], node->data.ipv6[6], node->data.ipv6[7],
                   node->data.ipv6[8], node->data.ipv6[9], node->data.ipv6[10], node->data.ipv6[11],
                   node->data.ipv6[12], node->data.ipv6[13], node->data.ipv6[14], node->data.ipv6[15]);
            break;
    }
}

// IPv6 address parsing helper
static int vfl_parse_ipv6_address(const char *addr_str, size_t len, uint8_t result[16]) {
    // Simple IPv6 address parser - handles basic formats like ::1, 2001:db8::1, etc.
    memset(result, 0, 16);
    
    if (len == 0) return -1;
    
    // Handle special case of "::" (all zeros)
    if (len == 2 && addr_str[0] == ':' && addr_str[1] == ':') {
        return 0;  // result is already all zeros
    }
    
    // Handle "::1" (loopback)
    if (len == 3 && strncmp(addr_str, "::1", 3) == 0) {
        result[15] = 1;  // ::1 has 1 in the last byte
        return 0;
    }
    
    // For now, only support these simple cases
    // TODO: Implement full IPv6 address parsing
    return -1;
}

// Check if a character sequence looks like an IPv6 address
static bool vfl_looks_like_ipv6(const char *str, size_t pos, size_t len) {
    // Look for patterns with colons that indicate IPv6
    bool has_colon = false;
    size_t colon_count = 0;
    
    for (size_t i = pos; i < len && i < pos + 40; i++) {  // IPv6 max length ~39 chars
        char c = str[i];
        if (c == ':') {
            has_colon = true;
            colon_count++;
        } else if (c == ' ' || c == ')' || c == '\t' || c == '\n') {
            break;  // End of potential IPv6 address
        } else if (!isxdigit(c)) {
            return false;  // Invalid character for IPv6
        }
    }
    
    return has_colon && colon_count >= 1;
}

// Lexer functions
static void vfl_skip_whitespace(vfl_parse_ctx_t *ctx) {
    while (ctx->pos < ctx->input_len && isspace(ctx->input[ctx->pos])) {
        if (ctx->input[ctx->pos] == '\n') {
            ctx->line++;
            ctx->column = 1;
        } else {
            ctx->column++;
        }
        ctx->pos++;
    }
}

static void vfl_skip_comment(vfl_parse_ctx_t *ctx) {
    if (ctx->pos < ctx->input_len && ctx->input[ctx->pos] == ';') {
        // Skip to end of line
        while (ctx->pos < ctx->input_len && ctx->input[ctx->pos] != '\n') {
            ctx->pos++;
            ctx->column++;
        }
    }
}

static vfl_token_t vfl_next_token(vfl_parse_ctx_t *ctx) {
    vfl_token_t token = {0};
    
    // Skip whitespace and comments
    do {
        vfl_skip_whitespace(ctx);
        vfl_skip_comment(ctx);
    } while (ctx->pos < ctx->input_len && (isspace(ctx->input[ctx->pos]) || ctx->input[ctx->pos] == ';'));
    
    token.line = ctx->line;
    token.column = ctx->column;
    
    if (ctx->pos >= ctx->input_len) {
        token.type = VFL_TOKEN_EOF;
        return token;
    }
    
    char c = ctx->input[ctx->pos];
    
    switch (c) {
        case '(':
            token.type = VFL_TOKEN_LPAREN;
            ctx->pos++;
            ctx->column++;
            break;
            
        case ')':
            token.type = VFL_TOKEN_RPAREN;
            ctx->pos++;
            ctx->column++;
            break;
            
        default:
            if (isdigit(c) || (c == '-' && ctx->pos + 1 < ctx->input_len && isdigit(ctx->input[ctx->pos + 1]))) {
                // Parse integer
                char *endptr;
                errno = 0;
                token.value.integer = strtoll(&ctx->input[ctx->pos], &endptr, 10);
                if (errno == ERANGE) {
                    token.type = VFL_TOKEN_ERROR;
                    snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Integer overflow at line %d", ctx->line);
                    return token;
                }
                
                int len = endptr - &ctx->input[ctx->pos];
                ctx->pos += len;
                ctx->column += len;
                token.type = VFL_TOKEN_INTEGER;
            } else if (c == ':' && vfl_looks_like_ipv6(ctx->input, ctx->pos, ctx->input_len)) {
                // Parse IPv6 address
                size_t start = ctx->pos;
                while (ctx->pos < ctx->input_len) {
                    char cur = ctx->input[ctx->pos];
                    if (isxdigit(cur) || cur == ':') {
                        ctx->pos++;
                        ctx->column++;
                    } else {
                        break;  // End of IPv6 address
                    }
                }
                
                size_t len = ctx->pos - start;
                if (vfl_parse_ipv6_address(&ctx->input[start], len, token.value.ipv6) < 0) {
                    token.type = VFL_TOKEN_ERROR;
                    snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Invalid IPv6 address at line %d", ctx->line);
                    return token;
                }
                
                token.type = VFL_TOKEN_IPV6;
            } else if (isalpha(c) || c == '-' || c == '_' || c == '=' || c == '!' || c == '>' || c == '<' ||
                       c == '+' || c == '*' || c == '/' || c == '%' || c == '&' || c == '|' || c == '^') {
                // Parse symbol
                size_t start = ctx->pos;
                while (ctx->pos < ctx->input_len && 
                       (isalnum(ctx->input[ctx->pos]) || ctx->input[ctx->pos] == '-' || ctx->input[ctx->pos] == '_' ||
                        ctx->input[ctx->pos] == '=' || ctx->input[ctx->pos] == '!' || ctx->input[ctx->pos] == '>' ||
                        ctx->input[ctx->pos] == '<' || ctx->input[ctx->pos] == '+' || ctx->input[ctx->pos] == '*' ||
                        ctx->input[ctx->pos] == '/' || ctx->input[ctx->pos] == '%' || ctx->input[ctx->pos] == '&' ||
                        ctx->input[ctx->pos] == '|' || ctx->input[ctx->pos] == '^')) {
                    ctx->pos++;
                    ctx->column++;
                }
                
                size_t len = ctx->pos - start;
                token.value.symbol = malloc(len + 1);
                if (!token.value.symbol) {
                    token.type = VFL_TOKEN_ERROR;
                    snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Memory allocation failed");
                    return token;
                }
                
                strncpy(token.value.symbol, &ctx->input[start], len);
                token.value.symbol[len] = '\0';
                token.type = VFL_TOKEN_SYMBOL;
            } else {
                token.type = VFL_TOKEN_ERROR;
                snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unexpected character '%c' at line %d", c, ctx->line);
            }
            break;
    }
    
    return token;
}

static void vfl_token_destroy(vfl_token_t *token) {
    if (token->type == VFL_TOKEN_SYMBOL) {
        free(token->value.symbol);
    }
    // IPv6 tokens don't need cleanup - they store bytes directly
}

// Parser functions
static vfl_node_t* vfl_parse_expression(vfl_parse_ctx_t *ctx);

static vfl_node_t* vfl_parse_list(vfl_parse_ctx_t *ctx) {
    vfl_node_t *list = vfl_node_create_list();
    if (!list) return NULL;
    
    // Skip opening paren (already consumed)
    
    while (true) {
        vfl_token_t token = vfl_next_token(ctx);
        
        if (token.type == VFL_TOKEN_EOF) {
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unexpected EOF, expected ')'");
            vfl_node_destroy(list);
            return NULL;
        }
        
        if (token.type == VFL_TOKEN_RPAREN) {
            break;
        }
        
        if (token.type == VFL_TOKEN_ERROR) {
            vfl_node_destroy(list);
            return NULL;
        }
        
        // Push back the token by adjusting position
        if (token.type == VFL_TOKEN_LPAREN) {
            ctx->pos--;
            ctx->column--;
        } else if (token.type == VFL_TOKEN_INTEGER) {
            // Calculate how many digits to back up
            int len = snprintf(NULL, 0, "%lld", (long long)token.value.integer);
            ctx->pos -= len;
            ctx->column -= len;
        } else if (token.type == VFL_TOKEN_SYMBOL) {
            ctx->pos -= strlen(token.value.symbol);
            ctx->column -= strlen(token.value.symbol);
            vfl_token_destroy(&token);
        } else if (token.type == VFL_TOKEN_IPV6) {
            // Rewind to start of IPv6 token
            // Find the start by scanning backwards for the first colon or hex digit
            while (ctx->pos > 0 && (isxdigit(ctx->input[ctx->pos - 1]) || ctx->input[ctx->pos - 1] == ':')) {
                ctx->pos--;
                ctx->column--;
            }
        }
        
        vfl_node_t *child = vfl_parse_expression(ctx);
        if (!child) {
            vfl_node_destroy(list);
            return NULL;
        }
        
        vfl_node_list_append(list, child);
    }
    
    return list;
}

static vfl_node_t* vfl_parse_expression(vfl_parse_ctx_t *ctx) {
    vfl_token_t token = vfl_next_token(ctx);
    
    switch (token.type) {
        case VFL_TOKEN_EOF:
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unexpected EOF");
            return NULL;
            
        case VFL_TOKEN_ERROR:
            return NULL;
            
        case VFL_TOKEN_RPAREN:
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unexpected ')'");
            return NULL;
            
        case VFL_TOKEN_LPAREN:
            return vfl_parse_list(ctx);
            
        case VFL_TOKEN_INTEGER:
            return vfl_node_create_integer(token.value.integer);
            
        case VFL_TOKEN_IPV6:
            return vfl_node_create_ipv6(token.value.ipv6);
            
        case VFL_TOKEN_SYMBOL: {
            // Check if it's a packet field
            vfl_field_type_t field_type = vfl_lookup_field(token.value.symbol);
            if (field_type != VFL_FIELD_MAX) {
                vfl_token_destroy(&token);
                return vfl_node_create_field(field_type);
            }
            
            // It's a regular symbol
            vfl_node_t *node = vfl_node_create_symbol(token.value.symbol);
            vfl_token_destroy(&token);
            return node;
        }
        
        default:
            snprintf(ctx->error_msg, sizeof(ctx->error_msg), "Unexpected token");
            return NULL;
    }
}

// Public API
vfl_node_t* vfl_parse(const char *input) {
    vfl_parse_ctx_t ctx = {
        .input = input,
        .input_len = strlen(input),
        .pos = 0,
        .line = 1,
        .column = 1,
        .error_msg = {0}
    };
    
    vfl_node_t *ast = vfl_parse_expression(&ctx);
    if (!ast) {
        fprintf(stderr, "Parse error: %s\n", ctx.error_msg);
        return NULL;
    }
    
    // Check for trailing tokens
    vfl_token_t token = vfl_next_token(&ctx);
    if (token.type != VFL_TOKEN_EOF) {
        fprintf(stderr, "Parse error: Unexpected trailing tokens\n");
        vfl_node_destroy(ast);
        vfl_token_destroy(&token);
        return NULL;
    }
    
    return ast;
}

// Parse from file
vfl_node_t* vfl_parse_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
        return NULL;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    // Read entire file
    char *input = malloc(size + 1);
    if (!input) {
        fprintf(stderr, "Error: Memory allocation failed\n");
        fclose(file);
        return NULL;
    }
    
    fread(input, 1, size, file);
    input[size] = '\0';
    fclose(file);
    
    vfl_node_t *ast = vfl_parse(input);
    free(input);
    
    return ast;
}