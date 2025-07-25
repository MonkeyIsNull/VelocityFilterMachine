#ifndef VFLISP_TYPES_H
#define VFLISP_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

// VFLisp AST node types
typedef enum {
    VFL_NODE_INTEGER,    // Integer literal
    VFL_NODE_SYMBOL,     // Symbol (function name, field name)
    VFL_NODE_LIST,       // List (function call)
    VFL_NODE_FIELD,      // Packet field access
    VFL_NODE_IPV6        // IPv6 address literal
} vfl_node_type_t;

// Forward declaration for recursive structure
typedef struct vfl_node vfl_node_t;

// Packet field types
typedef enum {
    // Legacy IPv4 fields (fixed offsets)
    VFL_FIELD_PROTO,     // IP protocol (offset 23)
    VFL_FIELD_SRC_IP,    // Source IPv4 (offset 26) - legacy
    VFL_FIELD_DST_IP,    // Destination IPv4 (offset 30) - legacy
    VFL_FIELD_SRC_PORT,  // Source port (offset 34)
    VFL_FIELD_DST_PORT,  // Destination port (offset 36)
    VFL_FIELD_ETHERTYPE, // Ethernet type (offset 12)
    VFL_FIELD_IP_LEN,    // IP length (offset 16)
    VFL_FIELD_TCP_FLAGS, // TCP flags (offset 47)
    
    // Enhanced IPv4/IPv6 fields (dynamic offsets)
    VFL_FIELD_IP_VERSION, // IP version field (offset 14, size 1)
    VFL_FIELD_SRC_IP4,   // Source IPv4 explicit (offset 26, size 4)
    VFL_FIELD_DST_IP4,   // Destination IPv4 explicit (offset 30, size 4)
    VFL_FIELD_SRC_IP6,   // Source IPv6 (offset varies, size 16)
    VFL_FIELD_DST_IP6,   // Destination IPv6 (offset varies, size 16)
    VFL_FIELD_NEXT_HDR,  // IPv6 next header field
    VFL_FIELD_HOP_LIMIT, // IPv6 hop limit
    
    // IPv6 extension header fields
    VFL_FIELD_HAS_EXT_HDR,    // Whether packet has extension headers (0/1)
    VFL_FIELD_EXT_HDR_COUNT,  // Number of extension headers
    VFL_FIELD_EXT_HDR_LEN,    // Total length of all extension headers
    VFL_FIELD_FINAL_PROTO,    // Final protocol after all extension headers
    VFL_FIELD_FRAG_ID,        // Fragment identification (from fragment header)
    VFL_FIELD_FRAG_OFFSET,    // Fragment offset (from fragment header)
    VFL_FIELD_FRAG_FLAGS,     // Fragment flags (more fragments bit)
    
    VFL_FIELD_MAX
} vfl_field_type_t;

// Address family for field information
typedef enum {
    VFL_ADDR_ANY = 0,     // Field works with any IP version
    VFL_ADDR_IPV4 = 4,    // IPv4-only field
    VFL_ADDR_IPV6 = 6     // IPv6-only field
} vfl_addr_family_t;

// Packet field information - enhanced for IPv6 support
typedef struct {
    const char *name;
    vfl_field_type_t type;
    uint16_t offset;            // Fixed offset (0 for dynamic)
    uint8_t size;               // Field size in bytes (1, 2, 4, 16)
    vfl_addr_family_t addr_family; // Address family requirement
    uint16_t (*offset_calc)(const uint8_t *packet, uint16_t len);  // Dynamic offset function
} vfl_field_info_t;

// Packet field definitions - enhanced for IPv6 support
static const vfl_field_info_t vfl_field_info[] = {
    // Legacy IPv4 fields (fixed offsets for backward compatibility)
    [VFL_FIELD_PROTO]     = {"proto",     VFL_FIELD_PROTO,     23, 1, VFL_ADDR_IPV4, NULL},
    [VFL_FIELD_SRC_IP]    = {"src-ip",    VFL_FIELD_SRC_IP,    26, 4, VFL_ADDR_IPV4, NULL},
    [VFL_FIELD_DST_IP]    = {"dst-ip",    VFL_FIELD_DST_IP,    30, 4, VFL_ADDR_IPV4, NULL},
    [VFL_FIELD_SRC_PORT]  = {"src-port",  VFL_FIELD_SRC_PORT,  34, 2, VFL_ADDR_ANY, NULL},
    [VFL_FIELD_DST_PORT]  = {"dst-port",  VFL_FIELD_DST_PORT,  36, 2, VFL_ADDR_ANY, NULL},
    [VFL_FIELD_ETHERTYPE] = {"ethertype", VFL_FIELD_ETHERTYPE, 12, 2, VFL_ADDR_ANY, NULL},
    [VFL_FIELD_IP_LEN]    = {"ip-len",    VFL_FIELD_IP_LEN,    16, 2, VFL_ADDR_IPV4, NULL},
    [VFL_FIELD_TCP_FLAGS] = {"tcp-flags", VFL_FIELD_TCP_FLAGS, 47, 1, VFL_ADDR_IPV4, NULL},
    
    // Enhanced IPv4/IPv6 fields
    [VFL_FIELD_IP_VERSION] = {"ip-version", VFL_FIELD_IP_VERSION, 14, 1, VFL_ADDR_ANY, NULL},
    [VFL_FIELD_SRC_IP4]   = {"src-ip4",   VFL_FIELD_SRC_IP4,   26, 4, VFL_ADDR_IPV4, NULL},
    [VFL_FIELD_DST_IP4]   = {"dst-ip4",   VFL_FIELD_DST_IP4,   30, 4, VFL_ADDR_IPV4, NULL},
    [VFL_FIELD_SRC_IP6]   = {"src-ip6",   VFL_FIELD_SRC_IP6,   0,  16, VFL_ADDR_IPV6, NULL},
    [VFL_FIELD_DST_IP6]   = {"dst-ip6",   VFL_FIELD_DST_IP6,   0,  16, VFL_ADDR_IPV6, NULL},
    [VFL_FIELD_NEXT_HDR]  = {"next-hdr",  VFL_FIELD_NEXT_HDR,  20, 1, VFL_ADDR_IPV6, NULL},
    [VFL_FIELD_HOP_LIMIT] = {"hop-limit", VFL_FIELD_HOP_LIMIT, 21, 1, VFL_ADDR_IPV6, NULL},
    
    // IPv6 extension header fields (dynamic offset calculation required)
    [VFL_FIELD_HAS_EXT_HDR]    = {"has-ext-hdr",    VFL_FIELD_HAS_EXT_HDR,    0, 1, VFL_ADDR_IPV6, NULL},
    [VFL_FIELD_EXT_HDR_COUNT]  = {"ext-hdr-count",  VFL_FIELD_EXT_HDR_COUNT,  0, 1, VFL_ADDR_IPV6, NULL},
    [VFL_FIELD_EXT_HDR_LEN]    = {"ext-hdr-len",    VFL_FIELD_EXT_HDR_LEN,    0, 2, VFL_ADDR_IPV6, NULL},
    [VFL_FIELD_FINAL_PROTO]    = {"final-proto",    VFL_FIELD_FINAL_PROTO,    0, 1, VFL_ADDR_IPV6, NULL},
    [VFL_FIELD_FRAG_ID]        = {"frag-id",        VFL_FIELD_FRAG_ID,        0, 4, VFL_ADDR_IPV6, NULL},
    [VFL_FIELD_FRAG_OFFSET]    = {"frag-offset",    VFL_FIELD_FRAG_OFFSET,    0, 2, VFL_ADDR_IPV6, NULL},
    [VFL_FIELD_FRAG_FLAGS]     = {"frag-flags",     VFL_FIELD_FRAG_FLAGS,     0, 1, VFL_ADDR_IPV6, NULL},
};

// Function types
typedef enum {
    VFL_FUNC_IF,      // if condition
    VFL_FUNC_AND,     // logical and
    VFL_FUNC_OR,      // logical or
    VFL_FUNC_NOT,     // logical not
    VFL_FUNC_EQ,      // equal
    VFL_FUNC_NE,      // not equal
    VFL_FUNC_GT,      // greater than
    VFL_FUNC_GE,      // greater than or equal
    VFL_FUNC_LT,      // less than
    VFL_FUNC_LE,      // less than or equal
    VFL_FUNC_ADD,     // addition
    VFL_FUNC_SUB,     // subtraction
    VFL_FUNC_MUL,     // multiplication
    VFL_FUNC_DIV,     // division
    VFL_FUNC_MOD,     // modulo
    VFL_FUNC_BAND,    // bitwise and
    VFL_FUNC_BOR,     // bitwise or
    VFL_FUNC_BXOR,    // bitwise xor
    VFL_FUNC_SHL,     // shift left
    VFL_FUNC_SHR,     // shift right
    VFL_FUNC_MAX
} vfl_func_type_t;

// Function information
typedef struct {
    const char *name;
    vfl_func_type_t type;
    int min_args;
    int max_args;  // -1 for unlimited
    bool is_logical;
} vfl_func_info_t;

// Function definitions
static const vfl_func_info_t vfl_func_info[] = {
    [VFL_FUNC_IF]   = {"if",   VFL_FUNC_IF,   3, 3,  false},
    [VFL_FUNC_AND]  = {"and",  VFL_FUNC_AND,  2, -1, true},
    [VFL_FUNC_OR]   = {"or",   VFL_FUNC_OR,   2, -1, true},
    [VFL_FUNC_NOT]  = {"not",  VFL_FUNC_NOT,  1, 1,  true},
    [VFL_FUNC_EQ]   = {"=",    VFL_FUNC_EQ,   2, 2,  false},
    [VFL_FUNC_NE]   = {"!=",   VFL_FUNC_NE,   2, 2,  false},
    [VFL_FUNC_GT]   = {">",    VFL_FUNC_GT,   2, 2,  false},
    [VFL_FUNC_GE]   = {">=",   VFL_FUNC_GE,   2, 2,  false},
    [VFL_FUNC_LT]   = {"<",    VFL_FUNC_LT,   2, 2,  false},
    [VFL_FUNC_LE]   = {"<=",   VFL_FUNC_LE,   2, 2,  false},
    [VFL_FUNC_ADD]  = {"+",    VFL_FUNC_ADD,  2, -1, false},
    [VFL_FUNC_SUB]  = {"-",    VFL_FUNC_SUB,  2, 2,  false},
    [VFL_FUNC_MUL]  = {"*",    VFL_FUNC_MUL,  2, -1, false},
    [VFL_FUNC_DIV]  = {"/",    VFL_FUNC_DIV,  2, 2,  false},
    [VFL_FUNC_MOD]  = {"%",    VFL_FUNC_MOD,  2, 2,  false},
    [VFL_FUNC_BAND] = {"&",    VFL_FUNC_BAND, 2, -1, false},
    [VFL_FUNC_BOR]  = {"|",    VFL_FUNC_BOR,  2, -1, false},
    [VFL_FUNC_BXOR] = {"^",    VFL_FUNC_BXOR, 2, -1, false},
    [VFL_FUNC_SHL]  = {"<<",   VFL_FUNC_SHL,  2, 2,  false},
    [VFL_FUNC_SHR]  = {">>",   VFL_FUNC_SHR,  2, 2,  false},
};

// AST node structure
struct vfl_node {
    vfl_node_type_t type;
    union {
        // Integer literal
        int64_t integer;
        
        // Symbol (function name or field name)
        struct {
            char *name;
            vfl_func_type_t func_type;  // Valid only for function symbols
        } symbol;
        
        // Packet field access
        struct {
            vfl_field_type_t field_type;
            const vfl_field_info_t *field_info;
        } field;
        
        // List (function call)
        struct {
            vfl_node_t **children;
            int count;
            int capacity;
        } list;
        
        // IPv6 address literal
        uint8_t ipv6[16];
    } data;
};

// Compilation context
typedef struct {
    uint8_t *bytecode;
    uint32_t bytecode_pos;
    uint32_t bytecode_capacity;
    uint32_t stack_depth;
    uint32_t max_stack_depth;
    int error_line;
    char error_msg[256];
} vfl_compile_ctx_t;

// Parsing context
typedef struct {
    const char *input;
    size_t input_len;
    size_t pos;
    int line;
    int column;
    char error_msg[256];
} vfl_parse_ctx_t;

// Token types for lexer
typedef enum {
    VFL_TOKEN_EOF,
    VFL_TOKEN_LPAREN,
    VFL_TOKEN_RPAREN,
    VFL_TOKEN_INTEGER,
    VFL_TOKEN_SYMBOL,
    VFL_TOKEN_IPV6,
    VFL_TOKEN_ERROR
} vfl_token_type_t;

// Token structure
typedef struct {
    vfl_token_type_t type;
    union {
        int64_t integer;
        char *symbol;
        uint8_t ipv6[16];  // IPv6 address bytes
    } value;
    int line;
    int column;
} vfl_token_t;

// Function prototypes
vfl_node_t* vfl_node_create(vfl_node_type_t type);
void vfl_node_destroy(vfl_node_t *node);
vfl_node_t* vfl_node_create_integer(int64_t value);
vfl_node_t* vfl_node_create_symbol(const char *name);
vfl_node_t* vfl_node_create_field(vfl_field_type_t field_type);
vfl_node_t* vfl_node_create_list(void);
void vfl_node_list_append(vfl_node_t *list, vfl_node_t *child);

// Field offset calculation functions
uint16_t vfl_get_field_offset(vfl_field_type_t field_type, const uint8_t *packet, uint16_t len);
bool vfl_field_supports_ip_version(vfl_field_type_t field_type, uint8_t ip_version);

// IPv6 extension header field extraction
uint64_t vfl_extract_ipv6_ext_field(vfl_field_type_t field_type, const uint8_t *packet, uint16_t len);


// Utility functions
vfl_field_type_t vfl_lookup_field(const char *name);
vfl_func_type_t vfl_lookup_function(const char *name);
const char* vfl_node_type_name(vfl_node_type_t type);
const char* vfl_field_type_name(vfl_field_type_t type);
const char* vfl_func_type_name(vfl_func_type_t type);

// Print AST for debugging
void vfl_node_print(const vfl_node_t *node, int indent);

// Parser functions
vfl_node_t* vfl_parse(const char *input);
vfl_node_t* vfl_parse_file(const char *filename);

// Compiler functions
int vfl_compile(vfl_node_t *ast, uint8_t **bytecode, uint32_t *bytecode_len, char *error_msg, size_t error_msg_size);
int vfl_compile_string(const char *source, uint8_t **bytecode, uint32_t *bytecode_len, char *error_msg, size_t error_msg_size);
int vfl_compile_file(const char *filename, uint8_t **bytecode, uint32_t *bytecode_len, char *error_msg, size_t error_msg_size);


#endif // VFLISP_TYPES_H