#ifndef VFM_H
#define VFM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


// Platform detection
#ifdef __APPLE__
    #include <TargetConditionals.h>
    #define VFM_PLATFORM_MACOS 1
    #ifdef __aarch64__
        #define VFM_APPLE_SILICON 1
    #endif
#elif defined(__linux__)
    #define VFM_PLATFORM_LINUX 1
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    #define VFM_PLATFORM_BSD 1
#endif

// CPU cache line size optimization
#ifdef VFM_APPLE_SILICON
    #define VFM_CACHE_LINE_SIZE 128  // Apple Silicon has 128-byte cache lines
#else
    #define VFM_CACHE_LINE_SIZE 64   // Most x86_64 CPUs
#endif

// Alignment and optimization macros
#define VFM_ALIGNED(x) __attribute__((aligned(x)))
#define VFM_CACHE_ALIGNED VFM_ALIGNED(VFM_CACHE_LINE_SIZE)
#define VFM_LIKELY(x) __builtin_expect(!!(x), 1)
#define VFM_UNLIKELY(x) __builtin_expect(!!(x), 0)
#define VFM_PREFETCH(addr, rw, locality) __builtin_prefetch(addr, rw, locality)

// Force inline for hot path functions
#ifdef __GNUC__
    #define VFM_ALWAYS_INLINE __attribute__((always_inline)) inline
#else
    #define VFM_ALWAYS_INLINE inline
#endif

// Error codes
typedef enum {
    VFM_SUCCESS = 0,
    VFM_ERROR_BOUNDS = -1,
    VFM_ERROR_LIMIT = -2,
    VFM_ERROR_STACK_OVERFLOW = -3,
    VFM_ERROR_STACK_UNDERFLOW = -4,
    VFM_ERROR_INVALID_OPCODE = -5,
    VFM_ERROR_DIVISION_BY_ZERO = -6,
    VFM_ERROR_INVALID_PROGRAM = -7,
    VFM_ERROR_NO_MEMORY = -8,
    VFM_ERROR_VERIFICATION_FAILED = -9
} vfm_error_t;

// Opcode definitions (copied from public header to avoid conflicts)
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
    
    // Stack-based comparisons (leave boolean result on stack)
    VFM_EQ,      // Equal comparison
    VFM_NE,      // Not equal
    VFM_GT,      // Greater than
    VFM_LT,      // Less than
    VFM_GE,      // Greater or equal
    VFM_LE,      // Less or equal
    
    // IPv6 and 128-bit operations
    VFM_LD128,   // Load 128-bit value from packet (IPv6 addresses)
    VFM_PUSH128, // Push 128-bit immediate value
    VFM_EQ128,   // Compare 128-bit values for equality
    VFM_NE128,   // Compare 128-bit values for inequality
    VFM_GT128,   // Greater than (128-bit)
    VFM_LT128,   // Less than (128-bit)
    VFM_GE128,   // Greater or equal (128-bit)
    VFM_LE128,   // Less or equal (128-bit)
    VFM_AND128,  // Bitwise AND (128-bit)
    VFM_OR128,   // Bitwise OR (128-bit)
    VFM_XOR128,  // Bitwise XOR (128-bit)
    VFM_JEQ128,  // Jump if equal (128-bit)
    VFM_JNE128,  // Jump if not equal (128-bit)
    VFM_JGT128,  // Jump if greater (128-bit)
    VFM_JLT128,  // Jump if less (128-bit)
    VFM_JGE128,  // Jump if greater or equal (128-bit)
    VFM_JLE128,  // Jump if less or equal (128-bit)
    VFM_IP_VER,  // Get IP version (4 or 6)
    VFM_IPV6_EXT,// Extract IPv6 extension header field
    VFM_HASH6,   // Hash IPv6 5-tuple
    
    VFM_OPCODE_MAX
};

// Instruction format helpers
typedef enum {
    VFM_FMT_NONE,      // No operands (e.g., ADD, POP)
    VFM_FMT_IMM8,      // 8-bit immediate
    VFM_FMT_IMM16,     // 16-bit immediate
    VFM_FMT_IMM32,     // 32-bit immediate
    VFM_FMT_IMM64,     // 64-bit immediate
    VFM_FMT_IMM128,    // 128-bit immediate (for IPv6 addresses)
    VFM_FMT_OFFSET16   // 16-bit offset (for jumps and packet access)
} vfm_format_t;

// Opcode names for debugging
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
    [VFM_MOD]        = "MOD",
    [VFM_EQ]         = "EQ",
    [VFM_NE]         = "NE",
    [VFM_GT]         = "GT",
    [VFM_LT]         = "LT",
    [VFM_GE]         = "GE",
    [VFM_LE]         = "LE",
    [VFM_LD128]      = "LD128",
    [VFM_PUSH128]    = "PUSH128",
    [VFM_EQ128]      = "EQ128",
    [VFM_NE128]      = "NE128",
    [VFM_GT128]      = "GT128",
    [VFM_LT128]      = "LT128",
    [VFM_GE128]      = "GE128",
    [VFM_LE128]      = "LE128",
    [VFM_AND128]     = "AND128",
    [VFM_OR128]      = "OR128",
    [VFM_XOR128]     = "XOR128",
    [VFM_JEQ128]     = "JEQ128",
    [VFM_JNE128]     = "JNE128",
    [VFM_JGT128]     = "JGT128",
    [VFM_JLT128]     = "JLT128",
    [VFM_JGE128]     = "JGE128",
    [VFM_JLE128]     = "JLE128",
    [VFM_HASH6]      = "HASH6",
    [VFM_IP_VER]     = "IP_VER",
    [VFM_IPV6_EXT]   = "IPV6_EXT"
};

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
    [VFM_MOD]        = VFM_FMT_NONE,
    [VFM_EQ]         = VFM_FMT_NONE,     // stack-based comparison
    [VFM_NE]         = VFM_FMT_NONE,     // stack-based comparison  
    [VFM_GT]         = VFM_FMT_NONE,     // stack-based comparison
    [VFM_LT]         = VFM_FMT_NONE,     // stack-based comparison
    [VFM_GE]         = VFM_FMT_NONE,     // stack-based comparison
    [VFM_LE]         = VFM_FMT_NONE,     // stack-based comparison
    [VFM_LD128]      = VFM_FMT_OFFSET16, // packet offset for 128-bit load
    [VFM_PUSH128]    = VFM_FMT_IMM128,   // 128-bit immediate value
    [VFM_EQ128]      = VFM_FMT_NONE,     // compares two 128-bit values on stack
    [VFM_NE128]      = VFM_FMT_NONE,
    [VFM_GT128]      = VFM_FMT_NONE,
    [VFM_LT128]      = VFM_FMT_NONE,
    [VFM_GE128]      = VFM_FMT_NONE,
    [VFM_LE128]      = VFM_FMT_NONE,
    [VFM_AND128]     = VFM_FMT_NONE,
    [VFM_OR128]      = VFM_FMT_NONE,
    [VFM_XOR128]     = VFM_FMT_NONE,
    [VFM_JEQ128]     = VFM_FMT_OFFSET16, // jump offset
    [VFM_JNE128]     = VFM_FMT_OFFSET16,
    [VFM_JGT128]     = VFM_FMT_OFFSET16,
    [VFM_JLT128]     = VFM_FMT_OFFSET16,
    [VFM_JGE128]     = VFM_FMT_OFFSET16,
    [VFM_JLE128]     = VFM_FMT_OFFSET16,
    [VFM_HASH6]      = VFM_FMT_NONE,     // computes IPv6 5-tuple hash
    [VFM_IP_VER]     = VFM_FMT_NONE,     // pushes IP version (4 or 6)
    [VFM_IPV6_EXT]   = VFM_FMT_IMM8      // extracts IPv6 extension header field (field type as immediate)
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
        case VFM_FMT_IMM128:   return 17;  // 1 byte opcode + 16 bytes IPv6 address
        case VFM_FMT_OFFSET16: return 3;
        default:               return 0;
    }
}

// Maximum limits
#define VFM_MAX_INSN 10000
#define VFM_MAX_STACK 256
#define VFM_MAX_PACKET 65535
#define VFM_MAX_PROGRAM_SIZE (64 * 1024)  // 64KB max program
#define VFM_FLOW_TABLE_SIZE 65536         // 64K flow entries

// Flow table entry
typedef struct vfm_flow_entry {
    uint64_t key;
    uint64_t value;
    uint64_t last_seen;
} VFM_CACHE_ALIGNED vfm_flow_entry_t;

// 128-bit value for IPv6 addresses and large integers
typedef struct vfm_u128 {
    uint64_t low;   // Lower 64 bits
    uint64_t high;  // Upper 64 bits
} vfm_u128_t;

// JIT Cache Data Structures
typedef struct vfm_program_hash {
    uint32_t hash_high;     // Upper 32 bits of program hash
    uint32_t hash_low;      // Lower 32 bits of program hash
    uint32_t length;        // Program length for collision detection
    uint32_t checksum;      // Simple XOR checksum for fast validation
} vfm_program_hash_t;

typedef struct vfm_jit_cache_entry {
    vfm_program_hash_t program_hash;   // Program identifier
    void *jit_code;                    // Compiled native code
    size_t jit_code_size;              // Actual size of compiled code
    uint32_t ref_count;                // Reference counting for cleanup
    uint32_t _pad1;                    // Padding
    uint64_t last_used;                // Timestamp for LRU eviction
    uint64_t hit_count;                // Usage statistics
    uint64_t compile_time_ns;          // Compilation time tracking
    struct vfm_jit_cache_entry *next;  // Hash table collision chain
} VFM_CACHE_ALIGNED vfm_jit_cache_entry_t;

// VM state structure - optimized for cache locality and platform-specific cache lines
typedef struct vfm_state {
    // Hot execution context - First cache line (optimized for Apple Silicon 128B cache lines)
    struct {
        // Instruction execution hot path (16 bytes)
        uint32_t pc;                    // Program counter
        uint32_t insn_count;           // Instruction count  
        uint32_t insn_limit;           // Instruction limit
        vfm_error_t error;             // Error state
        
        // Stack management (16 bytes)
        uint32_t sp;                   // 64-bit stack pointer
        uint32_t sp128;                // 128-bit stack pointer
        uint32_t stack_size;           // Stack size
        uint32_t stack128_size;        // 128-bit stack size
        
        // Packet bounds checking (8 bytes)
        uint16_t packet_len;           // Packet length
        uint16_t _pad1;                // Padding
        uint32_t _pad2;                // Padding
        
        // Frequently accessed pointers (24 bytes)
        const uint8_t *packet;         // Packet data pointer
        uint64_t *stack;               // Stack pointer
        const uint8_t *program;        // Program pointer
        
        // Program execution state (8 bytes)  
        uint32_t program_len;          // Program length
        uint32_t _pad3;                // Padding
        
        // 128-bit stack pointer and flow state (24 bytes)
        vfm_u128_t *stack128;          // 128-bit stack pointer
        vfm_flow_entry_t *flow_table;  // Flow table pointer
        uint32_t flow_table_mask;      // Flow table mask
        uint32_t _pad4;                // Padding
        
        // Remaining padding to optimize for 128B cache line (24 bytes remaining)
        uint64_t _pad5[3];             // Padding for cache line optimization
        
    } VFM_CACHE_ALIGNED hot;           // Total: 128 bytes (perfect fit for Apple Silicon)
    
    // Cold data - separate cache line(s)
    struct {
        // Registers for complex operations - cache line aligned for burst access
        uint64_t regs[16] VFM_CACHE_ALIGNED;
        
        // JIT compilation data
        void *jit_code;                // Compiled native code
        size_t jit_code_size;          // Size of JIT code
        bool jit_enabled;              // JIT compilation enabled
        struct vfm_jit_cache_entry *jit_cache_entry;  // Cache entry reference
        uint32_t _pad_jit;             // Padding
        
        // Platform-specific optimization hints
        struct {
            bool use_prefetch;         // Enable prefetching
            bool use_huge_pages;       // Use huge pages for flow table
            uint8_t prefetch_distance; // How far ahead to prefetch
            uint8_t _pad[5];           // Padding
        } hints;
        
        // Additional padding for future expansion
        uint64_t _pad_cold[8];         // Reserved for future use
        
    } VFM_CACHE_ALIGNED cold;
} vfm_state_t;

// Public API

// Initialize VM state
vfm_state_t* vfm_create(void);
void vfm_destroy(vfm_state_t *vm);

// Load program
int vfm_load_program(vfm_state_t *vm, const uint8_t *program, uint32_t len);

// Execute filter on packet
int vfm_execute(vfm_state_t *vm, const uint8_t *packet, uint16_t packet_len);

// Verify program safety
int vfm_verify(const uint8_t *program, uint32_t len);

// Extended verification with instruction counting
int vfm_verify_extended(const uint8_t *program, uint32_t len, uint32_t max_instructions);

// Disassemble program for debugging
void vfm_disassemble(const uint8_t *program, uint32_t len, char *output, size_t output_size);

// BPF compilation targets
typedef struct bpf_insn {
    uint16_t code;
    uint8_t jt;
    uint8_t jf;
    uint32_t k;
} bpf_insn_t;

typedef struct ebpf_insn {
    uint8_t code;
    uint8_t dst_reg:4;
    uint8_t src_reg:4;
    int16_t off;
    int32_t imm;
} ebpf_insn_t;

typedef struct bpf_program {
    uint32_t bf_len;
    bpf_insn_t *bf_insns;
} bpf_program_t;

// Compilation to various BPF targets
int vfm_to_bpf(const uint8_t *vfm_prog, uint32_t vfm_len, bpf_insn_t *bpf_prog, uint32_t *bpf_len);
int vfm_to_ebpf(const uint8_t *vfm_prog, uint32_t vfm_len, ebpf_insn_t *ebpf_prog, uint32_t *ebpf_len);
int vfm_to_cbpf(const uint8_t *vfm_prog, uint32_t vfm_len, bpf_program_t *prog);
int vfm_to_xdp(const uint8_t *vfm_prog, uint32_t vfm_len, char *c_code, size_t code_size);

// JIT compilation for x86-64
void* vfm_jit_compile_x86_64(const uint8_t *program, uint32_t len);
void vfm_jit_free(void *code, size_t size);
uint64_t vfm_jit_execute(void *jit_code, const uint8_t *packet, uint16_t packet_len);

// JIT compilation for ARM64
void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len);
bool vfm_jit_available_arm64(void);

// JIT Cache Functions
vfm_program_hash_t vfm_compute_program_hash(const uint8_t *program, uint32_t len);
bool vfm_program_hash_equal(const vfm_program_hash_t *a, const vfm_program_hash_t *b);
vfm_jit_cache_entry_t* vfm_jit_cache_lookup(const vfm_program_hash_t *hash);
vfm_jit_cache_entry_t* vfm_jit_cache_store(const vfm_program_hash_t *hash, 
                                           void *jit_code, size_t code_size);
void vfm_jit_cache_release(vfm_jit_cache_entry_t *entry);

// Platform-specific optimizations
void vfm_enable_optimizations(vfm_state_t *vm);

// Statistics and debugging
typedef struct vfm_stats {
    uint64_t packets_processed;
    uint64_t packets_accepted;
    uint64_t packets_dropped;
    uint64_t total_instructions;
    uint64_t cache_hits;
    uint64_t cache_misses;
    double avg_instructions_per_packet;
} vfm_stats_t;

void vfm_get_stats(const vfm_state_t *vm, vfm_stats_t *stats);
void vfm_reset_stats(vfm_state_t *vm);

// Flow table operations
int vfm_flow_table_init(vfm_state_t *vm, uint32_t size);
void vfm_flow_table_destroy(vfm_state_t *vm);
void vfm_flow_table_clear(vfm_state_t *vm);

// Utility functions
const char* vfm_error_string(vfm_error_t error);

// 128-bit utility functions
static inline vfm_u128_t vfm_u128_from_bytes(const uint8_t bytes[16]) {
    vfm_u128_t result;
    // IPv6 addresses are in network byte order (big-endian)
    result.high = ((uint64_t)bytes[0] << 56) | ((uint64_t)bytes[1] << 48) |
                  ((uint64_t)bytes[2] << 40) | ((uint64_t)bytes[3] << 32) |
                  ((uint64_t)bytes[4] << 24) | ((uint64_t)bytes[5] << 16) |
                  ((uint64_t)bytes[6] << 8)  | ((uint64_t)bytes[7]);
    result.low  = ((uint64_t)bytes[8] << 56) | ((uint64_t)bytes[9] << 48) |
                  ((uint64_t)bytes[10] << 40) | ((uint64_t)bytes[11] << 32) |
                  ((uint64_t)bytes[12] << 24) | ((uint64_t)bytes[13] << 16) |
                  ((uint64_t)bytes[14] << 8)  | ((uint64_t)bytes[15]);
    return result;
}

static inline bool vfm_u128_eq(vfm_u128_t a, vfm_u128_t b) {
    return a.high == b.high && a.low == b.low;
}

static inline bool vfm_u128_ne(vfm_u128_t a, vfm_u128_t b) {
    return !vfm_u128_eq(a, b);
}

static inline bool vfm_u128_gt(vfm_u128_t a, vfm_u128_t b) {
    return (a.high > b.high) || (a.high == b.high && a.low > b.low);
}

static inline bool vfm_u128_lt(vfm_u128_t a, vfm_u128_t b) {
    return (a.high < b.high) || (a.high == b.high && a.low < b.low);
}

static inline bool vfm_u128_ge(vfm_u128_t a, vfm_u128_t b) {
    return vfm_u128_eq(a, b) || vfm_u128_gt(a, b);
}

static inline bool vfm_u128_le(vfm_u128_t a, vfm_u128_t b) {
    return vfm_u128_eq(a, b) || vfm_u128_lt(a, b);
}

static inline vfm_u128_t vfm_u128_and(vfm_u128_t a, vfm_u128_t b) {
    vfm_u128_t result;
    result.high = a.high & b.high;
    result.low = a.low & b.low;
    return result;
}

static inline vfm_u128_t vfm_u128_or(vfm_u128_t a, vfm_u128_t b) {
    vfm_u128_t result;
    result.high = a.high | b.high;
    result.low = a.low | b.low;
    return result;
}

static inline vfm_u128_t vfm_u128_xor(vfm_u128_t a, vfm_u128_t b) {
    vfm_u128_t result;
    result.high = a.high ^ b.high;
    result.low = a.low ^ b.low;
    return result;
}

// Platform-specific timing functions
#ifdef VFM_PLATFORM_MACOS
    #include <mach/mach_time.h>
    typedef uint64_t vfm_time_t;
    
    static inline vfm_time_t vfm_get_time(void) {
        return mach_absolute_time();
    }
    
    static inline double vfm_time_to_ns(vfm_time_t time) {
        static mach_timebase_info_data_t timebase = {0};
        if (timebase.denom == 0) {
            mach_timebase_info(&timebase);
        }
        return (double)time * timebase.numer / timebase.denom;
    }
#else
    #include <time.h>
    typedef struct timespec vfm_time_t;
    
    static inline vfm_time_t vfm_get_time(void) {
        vfm_time_t ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return ts;
    }
    
    static inline double vfm_time_to_ns(vfm_time_t time) {
        return time.tv_sec * 1000000000.0 + time.tv_nsec;
    }
#endif

// Batch processing API for better performance
typedef struct vfm_batch {
    const uint8_t **packets;
    uint16_t *lengths;
    uint8_t *results;  // 0 = drop, 1 = accept
    uint32_t count;
} vfm_batch_t;

int vfm_execute_batch(vfm_state_t *vm, vfm_batch_t *batch);

#endif // VFM_H