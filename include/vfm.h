/*
 * VFM - Velocity Filter Machine
 * High-performance packet filtering virtual machine
 * 
 * Single header library - include this file and optionally define VFM_IMPLEMENTATION
 * before including to get the implementation.
 * 
 * Example usage:
 *   #define VFM_IMPLEMENTATION
 *   #include "vfm.h"
 */

#ifndef VFM_SINGLE_HEADER_H
#define VFM_SINGLE_HEADER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <inttypes.h>

// Platform-specific system includes
#ifdef VFM_PLATFORM_LINUX
    #ifndef _POSIX_C_SOURCE
        #define _POSIX_C_SOURCE 200809L  /* For clock_gettime, strdup, and other POSIX functions */
    #endif
    #ifndef _DEFAULT_SOURCE
        #define _DEFAULT_SOURCE  /* For sysconf and other system functions */
    #endif
    #ifndef _ISOC11_SOURCE
        #define _ISOC11_SOURCE  /* For aligned_alloc and other C11 functions */
    #endif
    #include <sched.h>
    #include <unistd.h>
    #include <pthread.h>
    #include <time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

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

// Aligned allocation compatibility wrapper
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L && !defined(__STDC_NO_ATOMICS__)
    // C11 aligned_alloc is available
    #include <stdlib.h>
    #define VFM_ALIGNED_ALLOC(alignment, size) aligned_alloc(alignment, size)
#elif defined(VFM_PLATFORM_LINUX) || defined(_POSIX_C_SOURCE)
    // Use POSIX posix_memalign as fallback
    #include <stdlib.h>
    static inline void* vfm_aligned_alloc(size_t alignment, size_t size) {
        void *ptr = NULL;
        if (posix_memalign(&ptr, alignment, size) == 0) {
            return ptr;
        }
        return NULL;
    }
    #define VFM_ALIGNED_ALLOC(alignment, size) vfm_aligned_alloc(alignment, size)
#else
    // Fallback to regular malloc (may not be aligned)
    #include <stdlib.h>
    #define VFM_ALIGNED_ALLOC(alignment, size) malloc(size)
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

// Maximum limits
#define VFM_MAX_INSN 10000
#define VFM_MAX_STACK 256
#define VFM_STACK_SIZE 256
#define VFM_MAX_PACKET 65535
#define VFM_MAX_PROGRAM_SIZE (64 * 1024)  // 64KB max program
#define VFM_FLOW_TABLE_SIZE 65536         // 64K flow entries

// 128-bit value for IPv6 addresses and large integers
typedef struct vfm_u128 {
    uint64_t low;   // Lower 64 bits
    uint64_t high;  // Upper 64 bits
} vfm_u128_t;

// Opcodes
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
    VFM_AND32,   // 32-bit bitwise AND
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
    VFM_NE,      // Not equal comparison
    VFM_GT,      // Greater than comparison
    VFM_LT,      // Less than comparison
    VFM_GE,      // Greater or equal comparison
    VFM_LE,      // Less or equal comparison
    
    // IPv6 support opcodes (128-bit operations)
    VFM_LD128,   // Load 128-bit value from packet (IPv6 addresses)
    VFM_PUSH128, // Push 128-bit immediate value
    VFM_EQ128,   // Compare 128-bit values for equality
    VFM_NE128,   // Compare 128-bit values for inequality
    VFM_GT128,   // Compare 128-bit values (greater than)
    VFM_LT128,   // Compare 128-bit values (less than)
    VFM_GE128,   // Compare 128-bit values (greater or equal)
    VFM_LE128,   // Compare 128-bit values (less or equal)
    VFM_AND128,  // 128-bit bitwise AND (for IPv6 subnet masks)
    VFM_OR128,   // 128-bit bitwise OR
    VFM_XOR128,  // 128-bit bitwise XOR
    VFM_JEQ128,  // Jump if 128-bit values equal
    VFM_JNE128,  // Jump if 128-bit values not equal
    VFM_JGT128,  // Jump if first 128-bit value > second
    VFM_JLT128,  // Jump if first 128-bit value < second
    VFM_JGE128,  // Jump if first 128-bit value >= second
    VFM_JLE128,  // Jump if first 128-bit value <= second
    VFM_IP_VER,  // Get IP version from packet (4 or 6)
    VFM_IPV6_EXT,// Extract IPv6 extension header field
    VFM_HASH6,   // Hash IPv6 5-tuple

    // ARM64 NEON optimized operations for Phase 2.1.3
    VFM_BULK_LOAD128,    // Bulk load multiple 128-bit values using NEON LDP
    VFM_PARALLEL_EQ128,  // Parallel comparison of multiple 128-bit pairs
    VFM_STACK_PREFETCH,  // Prefetch stack regions for cache optimization
    
    // Additional opcodes for JIT optimizations
    VFM_EQ32,            // 32-bit equality comparison
    VFM_PUSH32,          // Push 32-bit value

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

// Phase 2.3: Flow table statistics for performance monitoring
typedef struct vfm_flow_stats {
    uint64_t lookups;       // Total number of lookups
    uint64_t hits;          // Successful lookups
    uint64_t misses;        // Failed lookups
    uint64_t collisions;    // Hash collisions
    uint64_t evictions;     // LRU evictions
    uint32_t load_factor;   // Current load percentage (0-100)
    double hit_rate;        // Cache hit rate (0.0-1.0)
} vfm_flow_stats_t;

// Phase 3.2: Adaptive JIT optimization structures
typedef struct vfm_instruction_profile {
    uint64_t execution_count;      // How many times this instruction was executed
    uint64_t cycle_count;          // Estimated CPU cycles consumed
    uint32_t branch_taken_count;   // For conditional instructions
    uint32_t branch_not_taken_count;
    uint32_t cache_misses;         // Memory access pattern data
    uint32_t _pad;                 // Padding
} vfm_instruction_profile_t;

typedef struct vfm_execution_profile {
    // Per-instruction profiling data
    vfm_instruction_profile_t *instruction_profiles;
    uint32_t instruction_count;
    
    // Hot path detection
    uint32_t *hot_paths;           // Most frequently executed instruction sequences
    uint32_t hot_path_count;
    
    // Packet pattern analysis - Phase 3.2.2 enhanced patterns
    struct {
        uint64_t ipv4_packets;     // IPv4 vs IPv6 packet distribution
        uint64_t ipv6_packets;
        uint64_t tcp_packets;      // Protocol distribution
        uint64_t udp_packets;
        uint64_t icmp_packets;     // ICMP packets
        uint64_t icmpv6_packets;   // ICMPv6 packets
        uint64_t dns_packets;      // DNS packets (UDP port 53/5353)
        uint64_t other_packets;
        
        // TCP-specific patterns
        uint64_t tcp_syn_packets;  // TCP SYN packets
        uint64_t tcp_ack_packets;  // TCP ACK packets
        
        // Packet size distribution
        uint64_t small_packets;    // <= 64 bytes
        uint64_t medium_packets;   // 65-512 bytes
        uint64_t large_packets;    // 513-1500 bytes
        uint64_t jumbo_packets;    // > 1500 bytes
        
        // Network patterns
        uint32_t common_src_subnet; // Most common source subnet (/24)
        uint32_t src_subnet_count;   // Count for common subnet
        uint64_t burst_packets;      // Packets in bursts (< 1ms apart)
        
        uint64_t average_packet_size;
        uint64_t total_packets;
    } packet_patterns;
    
    // Branch prediction hints
    struct {
        uint32_t *likely_taken;    // Instructions where branches are usually taken
        uint32_t *likely_not_taken;
        uint32_t hint_count;
    } branch_hints;
    
    // Memory access patterns
    struct {
        uint64_t stack_accesses;   // Stack vs heap access patterns
        uint64_t heap_accesses;
        uint64_t flow_table_hits;
        uint64_t flow_table_misses;
    } memory_patterns;
    
} vfm_execution_profile_t;

// JIT optimization levels
typedef enum {
    VFM_JIT_OPT_NONE = 0,         // No optimization
    VFM_JIT_OPT_BASIC = 1,        // Basic optimizations
    VFM_JIT_OPT_ADAPTIVE = 2,     // Profile-guided optimization
    VFM_JIT_OPT_AGGRESSIVE = 3    // Maximum optimization
} vfm_jit_optimization_level_t;

// Phase 3.1: Multi-core VFM architecture
typedef struct vfm_core_context {
    // Core-local execution state - must be isolated per thread
    struct {
        uint32_t pc;                // Program counter
        uint32_t insn_count;        // Instructions executed
        uint32_t insn_limit;        // Instruction limit
        vfm_error_t error;          // Execution error state
        uint32_t sp;                // Stack pointer
        uint16_t packet_len;        // Current packet length
        uint16_t _pad1;             // Padding
    } VFM_CACHE_ALIGNED hot;
    
    // Core-local packet data
    const uint8_t *packet;          // Current packet being processed
    
    // Per-core stack - isolated to prevent false sharing
    uint64_t *stack VFM_ALIGNED(128);  // Aligned to cache line
    uint32_t stack_size;
    uint32_t core_id;               // Core identifier
    
    // Per-core registers - isolated per thread
    uint64_t regs[16] VFM_CACHE_ALIGNED;
    
    // Core-local flow statistics
    vfm_flow_stats_t flow_stats VFM_CACHE_ALIGNED;
    
    // JIT compiled code for this core
    void *jit_code;
    
} VFM_CACHE_ALIGNED vfm_core_context_t;

// Shared read-only data across all cores
typedef struct vfm_shared_context {
    // Program data (read-only, shared across cores)
    const uint8_t *program;
    uint32_t program_len;
    uint32_t _pad1;
    
    // Shared JIT cache (thread-safe access)
    void *jit_code;
    size_t jit_code_size;
    bool jit_enabled;
    struct vfm_jit_cache_entry *jit_cache_entry;
    
    // Platform hints (read-only after initialization)
    struct {
        bool use_prefetch;
        bool use_huge_pages;
        uint8_t prefetch_distance;
        
        // Phase 3.2.2: Packet pattern optimization flags
        bool optimize_for_ipv4;        // Optimize for IPv4-heavy workloads
        bool optimize_for_ipv6;        // Optimize for IPv6-heavy workloads
        bool optimize_for_tcp;         // Optimize for TCP-heavy workloads
        bool optimize_for_small_packets; // Optimize for small packet workloads
        bool optimize_for_bursts;      // Optimize for burst traffic patterns
        uint8_t _pad[0];               // No padding needed now
    } hints;
    
    // Multi-core configuration
    uint32_t num_cores;             // Number of cores to use
    uint32_t numa_node;             // NUMA node for memory allocation
    
    // Phase 3.2: Adaptive JIT optimization
    vfm_execution_profile_t *execution_profile;  // Runtime profiling data
    vfm_jit_optimization_level_t opt_level;      // Current optimization level
    uint32_t recompilation_threshold;            // When to trigger recompilation
    uint64_t total_executions;                   // Total filter executions
    
} VFM_CACHE_ALIGNED vfm_shared_context_t;

// Phase 3.1.2: Lock-free flow table entry with atomic operations
typedef struct vfm_flow_entry {
    _Atomic(uint64_t) key;           // Hash key (atomic for lock-free access)
    _Atomic(uint64_t) value;         // Associated value (atomic)
    _Atomic(uint64_t) last_seen;     // Timestamp for LRU eviction (atomic)
    _Atomic(uint32_t) collision_count; // Number of collisions for this slot (atomic)
    uint32_t _pad;                   // Padding to 32-byte alignment
} VFM_CACHE_ALIGNED vfm_flow_entry_t;

// Phase 3.1: Multi-core VFM state structure
typedef struct vfm_multicore_state {
    // Shared context (read-only after initialization)
    vfm_shared_context_t *shared;
    
    // Per-core contexts (one per thread)
    vfm_core_context_t **cores;
    
    // Shared flow table (thread-safe access required)
    vfm_flow_entry_t *flow_table;
    uint32_t flow_table_mask;
    
    // Multi-threading configuration
    uint32_t num_cores;
    uint32_t active_cores;          // Currently active cores
    
    // Thread management
    pthread_t *threads;             // Worker threads
    volatile bool shutdown;         // Shutdown signal
    
    // Performance monitoring across all cores
    struct {
        uint64_t total_packets;     // Total packets processed
        uint64_t total_instructions; // Total instructions executed
        uint64_t core_utilization[16]; // Per-core utilization (max 16 cores)
    } global_stats;
    
} VFM_CACHE_ALIGNED vfm_multicore_state_t;

// Legacy single-core VM state structure - optimized for cache locality
typedef struct vfm_state {
    // Hot data - frequently accessed during execution
    struct {
        // Program counter and execution state
        uint32_t pc;
        uint32_t insn_count;
        uint32_t insn_limit;
        vfm_error_t error;
        
        // Stack pointer
        uint32_t sp;
        uint32_t sp128;             // 128-bit stack pointer
        
        // Packet bounds (hot for bounds checking)
        uint16_t packet_len;
        uint16_t _pad1;  // Padding for alignment
        
        // Packet data pointer
        const uint8_t *packet;
        
        // Program data
        const uint8_t *program;
        uint32_t program_len;
        uint32_t _pad2;
        
        // Stack memory
        uint64_t *stack;
        uint32_t stack_size;
        vfm_u128_t *stack128;
        uint32_t stack128_size;
        
        // Flow state table (moved to hot for Phase 2.3 cache optimization)
        vfm_flow_entry_t *flow_table;
        uint32_t flow_table_mask;  // Size - 1 for fast modulo
        
        // Phase 2.3: Flow table performance tracking
        struct {
            uint64_t lookups;       // Total number of lookups
            uint64_t hits;          // Successful lookups
            uint64_t misses;        // Failed lookups
            uint64_t collisions;    // Hash collisions
            uint64_t evictions;     // LRU evictions
            uint32_t load_factor;   // Current load percentage (0-100)
            uint32_t _pad;          // Padding
        } flow_stats;
    } VFM_CACHE_ALIGNED hot;
    
    // Cold data - less frequently accessed
    struct {
        // JIT compilation cache
        void *jit_code;             // Compiled native code (NULL if not compiled)
        size_t jit_code_size;       // Size of JIT code for cleanup
        bool jit_enabled;           // Whether to attempt JIT compilation
        struct vfm_jit_cache_entry *jit_cache_entry;  // Reference to cached entry
        
        // Platform-specific optimization hints
        struct {
            bool use_prefetch;      // Enable prefetching
            bool use_huge_pages;    // Use huge pages for flow table
            uint8_t prefetch_distance;  // How far ahead to prefetch
            uint8_t _pad[5];        // Padding to 8 bytes
        } hints;
        
        uint64_t _pad_cold[4];      // Padding for future expansion
    } cold;
    
    // Registers (faster than pure stack) - cache line aligned  
    uint64_t regs[16] VFM_CACHE_ALIGNED;
    
    // 128-bit stack for IPv6 operations
    vfm_u128_t *stack128;
    uint32_t stack128_size;
    uint32_t _pad4;
    
    // Platform-specific optimization hints (legacy compatibility)
    struct {
        bool use_prefetch;      // Enable prefetching
        bool use_huge_pages;    // Use huge pages for flow table
        uint8_t prefetch_distance;  // How far ahead to prefetch
        uint8_t _pad[5];        // Padding to 8 bytes
    } hints;
} vfm_state_t;

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

// Opcode names for debugging (stub implementation)
__attribute__((unused)) static const char *vfm_opcode_names[] = {
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
    [VFM_AND32]      = "AND32",
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
    [VFM_IPV6_EXT]   = "IPV6_EXT",
    [VFM_BULK_LOAD128]   = "BULK_LOAD128",
    [VFM_PARALLEL_EQ128] = "PARALLEL_EQ128",
    [VFM_STACK_PREFETCH] = "STACK_PREFETCH",
    [VFM_EQ32]       = "EQ32",
    [VFM_PUSH32]     = "PUSH32",
};

// Opcode format information (stub implementation)
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
    [VFM_AND32]      = VFM_FMT_NONE,
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
    [VFM_IPV6_EXT]   = VFM_FMT_IMM8,     // extracts IPv6 extension header field (field type as immediate)
    [VFM_BULK_LOAD128]   = VFM_FMT_IMM8, // bulk load operations
    [VFM_PARALLEL_EQ128] = VFM_FMT_IMM8, // parallel comparison count
    [VFM_STACK_PREFETCH] = VFM_FMT_IMM8, // prefetch depth
    [VFM_EQ32]       = VFM_FMT_NONE,     // 32-bit equality comparison
    [VFM_PUSH32]     = VFM_FMT_IMM32,    // 32-bit immediate value
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

// JIT Cache Configuration
#define VFM_JIT_CACHE_MAX_ENTRIES 1024        // Maximum cached programs
#define VFM_JIT_CACHE_MAX_MEMORY_MB 64        // Maximum memory usage
#define VFM_JIT_CACHE_BUCKET_COUNT 256        // Hash table buckets
#define VFM_JIT_CACHE_POOL_SIZES 4            // Number of pool sizes

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

typedef struct vfm_jit_cache_stats {
    uint64_t cache_hits;               // Successful cache lookups
    uint64_t cache_misses;             // Failed cache lookups
    uint64_t total_compilations;       // Total JIT compilations performed
    uint64_t memory_used;              // Current memory usage
    uint64_t memory_peak;              // Peak memory usage
    uint64_t evictions;                // Cache evictions performed
    double avg_compile_time_ms;        // Average compilation time
    double cache_hit_ratio;            // Hit ratio percentage
    uint32_t active_entries;           // Current cache entries
    uint32_t _pad;                     // Padding
} vfm_jit_cache_stats_t;

typedef struct vfm_jit_cache_config {
    uint32_t max_entries;              // Maximum cache entries
    size_t max_memory_mb;              // Memory limit in MB
    uint32_t bucket_count;             // Hash table size
    bool enable_stats;                 // Enable statistics collection
    bool enable_prefetch;              // Enable prefetching
    uint32_t eviction_batch_size;      // LRU eviction batch size
    uint8_t _pad[3];                   // Padding
} vfm_jit_cache_config_t;

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

// Statistics and debugging
typedef struct vfm_stats {
    uint64_t packets_processed;
    uint64_t packets_accepted;
    uint64_t packets_dropped;
    uint64_t total_instructions;
    uint64_t cache_hits;
    uint64_t cache_misses;
    double avg_instructions_per_packet;
    uint64_t instructions_executed;     // Total instructions executed
    uint64_t flow_hits;                 // Flow table hits
    uint64_t flow_misses;               // Flow table misses
    uint64_t total_execution_time_ns;   // Total execution time in nanoseconds
} vfm_stats_t;

// Batch processing API for better performance
typedef struct vfm_batch {
    const uint8_t **packets;
    uint16_t *lengths;
    uint8_t *results;  // 0 = drop, 1 = accept
    uint32_t count;
} vfm_batch_t;

// Platform-specific timing functions - unified to always return uint64_t nanoseconds
#ifdef VFM_PLATFORM_MACOS
    #include <mach/mach_time.h>
    
    static inline uint64_t vfm_get_time(void) {
        static mach_timebase_info_data_t timebase = {0};
        if (timebase.denom == 0) {
            mach_timebase_info(&timebase);
        }
        uint64_t abs_time = mach_absolute_time();
        return abs_time * timebase.numer / timebase.denom;
    }
#else
    static inline uint64_t vfm_get_time(void) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
    }
#endif

// Convert nanosecond timestamp to double for calculations
static inline double vfm_time_to_ns(uint64_t time) {
    return (double)time;
}

// Public API declarations

// Initialize VM state
vfm_state_t* vfm_create(void);
void vfm_destroy(vfm_state_t *vm);

// Phase 3.1: Multi-core VFM API
vfm_multicore_state_t* vfm_multicore_create(uint32_t num_cores);
void vfm_multicore_destroy(vfm_multicore_state_t *mc_vm);
int vfm_multicore_load_program(vfm_multicore_state_t *mc_vm, const uint8_t *program, uint32_t len);
int vfm_multicore_execute_batch(vfm_multicore_state_t *mc_vm, vfm_batch_t *batch);
void vfm_multicore_get_stats(const vfm_multicore_state_t *mc_vm, vfm_stats_t *stats);

// Core affinity and NUMA functions
int vfm_multicore_set_thread_affinity(vfm_multicore_state_t *mc_vm, bool enable);
int vfm_multicore_set_numa_node(vfm_multicore_state_t *mc_vm, uint32_t numa_node);

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

// Phase 3.2.3: Adaptive JIT compilation with profile-guided optimization
void* vfm_jit_compile_arm64_adaptive(const uint8_t *program, uint32_t len, 
                                     vfm_execution_profile_t *profile);
void* vfm_jit_compile_x86_64_adaptive(const uint8_t *program, uint32_t len, 
                                      vfm_execution_profile_t *profile);

// JIT Cache Management
int vfm_jit_cache_init(const vfm_jit_cache_config_t *config);
void vfm_jit_cache_destroy(void);
int vfm_jit_cache_configure(const vfm_jit_cache_config_t *config);

// Program Hash Functions
vfm_program_hash_t vfm_compute_program_hash(const uint8_t *program, uint32_t len);
bool vfm_program_hash_equal(const vfm_program_hash_t *a, const vfm_program_hash_t *b);

// Cache Operations
vfm_jit_cache_entry_t* vfm_jit_cache_lookup(const vfm_program_hash_t *hash);
vfm_jit_cache_entry_t* vfm_jit_cache_store(const vfm_program_hash_t *hash, 
                                           void *jit_code, size_t code_size);
void vfm_jit_cache_release(vfm_jit_cache_entry_t *entry);

// Cache Statistics and Monitoring
void vfm_jit_cache_get_stats(vfm_jit_cache_stats_t *stats);
void vfm_jit_cache_reset_stats(void);
void vfm_jit_cache_print_stats(void);

// JIT Cache Internal Functions (implementation only)
void vfm_jit_cache_evict_lru(size_t bytes_needed);
void vfm_jit_cache_update_lru(vfm_jit_cache_entry_t *entry);

// Platform-specific optimizations
void vfm_enable_optimizations(vfm_state_t *vm);

// Statistics and debugging
void vfm_get_stats(const vfm_state_t *vm, vfm_stats_t *stats);
void vfm_reset_stats(vfm_state_t *vm);

// Flow table operations
int vfm_flow_table_init(vfm_state_t *vm, uint32_t size);
void vfm_flow_table_destroy(vfm_state_t *vm);
void vfm_flow_table_get_stats(const vfm_state_t *vm, vfm_flow_stats_t *stats);

// Function declarations for external stub implementations (only for functions not static in vfm.c)
// Note: Many functions like update_execution_profile, worker_thread, etc. are implemented as static in vfm.c

// Hash functions for testing (cross-platform optimized)
uint64_t vfm_hash_ipv4_5tuple(const uint8_t *packet, uint16_t len);
uint64_t vfm_hash_ipv6_5tuple(const uint8_t *packet, uint16_t len);
void vfm_flow_table_clear(vfm_state_t *vm);

// Utility functions
const char* vfm_error_string(vfm_error_t error);

// Batch processing
int vfm_execute_batch(vfm_state_t *vm, vfm_batch_t *batch);

#ifdef __cplusplus
}
#endif

// Implementation section - only included if VFM_IMPLEMENTATION is defined
#ifdef VFM_IMPLEMENTATION

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>

// Platform-specific includes
#ifdef VFM_PLATFORM_MACOS
    #include <mach/mach.h>
    #include <mach/vm_map.h>
#endif

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
    [VFM_AND32]      = "AND32",
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
    [VFM_IP_VER]     = "IP_VER",
    [VFM_IPV6_EXT]   = "IPV6_EXT",
    [VFM_HASH6]      = "HASH6",
    [VFM_BULK_LOAD128]   = "BULK_LOAD128",
    [VFM_PARALLEL_EQ128] = "PARALLEL_EQ128", 
    [VFM_STACK_PREFETCH] = "STACK_PREFETCH"
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
    [VFM_IP_VER]     = VFM_FMT_NONE,     // pushes IP version (4 or 6)
    [VFM_IPV6_EXT]   = VFM_FMT_IMM8,     // extracts IPv6 extension header field (field type as immediate)
    [VFM_HASH6]      = VFM_FMT_NONE      // computes IPv6 5-tuple hash
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

// Hash function for 5-tuple (optimized for common use cases)
static VFM_ALWAYS_INLINE uint64_t hash_5tuple(const uint8_t *packet, uint16_t len) {
    if (VFM_UNLIKELY(len < 34)) return 0;  // Too short for IP header
    
    // Simple but fast hash of IP 5-tuple
    uint64_t hash = 0;
    uint32_t src_ip = *(uint32_t*)(packet + 26);
    uint32_t dst_ip = *(uint32_t*)(packet + 30);
    uint16_t src_port = *(uint16_t*)(packet + 34);
    uint16_t dst_port = *(uint16_t*)(packet + 36);
    uint8_t protocol = packet[23];
    
    // FNV-1a hash
    hash = 14695981039346656037ULL;
    hash ^= src_ip; hash *= 1099511628211ULL;
    hash ^= dst_ip; hash *= 1099511628211ULL;
    hash ^= src_port; hash *= 1099511628211ULL;
    hash ^= dst_port; hash *= 1099511628211ULL;
    hash ^= protocol; hash *= 1099511628211ULL;
    
    return hash;
}

// Flow table operations
static VFM_ALWAYS_INLINE uint64_t flow_table_get(vfm_state_t *vm, uint64_t key) {
    if (VFM_UNLIKELY(!vm->flow_table)) return 0;
    
    uint32_t index = key & vm->flow_table_mask;
    vfm_flow_entry_t *entry = &vm->flow_table[index];
    
    if (VFM_LIKELY(entry->key == key)) {
        return entry->value;
    }
    
    return 0;
}

static VFM_ALWAYS_INLINE void flow_table_set(vfm_state_t *vm, uint64_t key, uint64_t value) {
    if (VFM_UNLIKELY(!vm->flow_table)) return;
    
    uint32_t index = key & vm->flow_table_mask;
    vfm_flow_entry_t *entry = &vm->flow_table[index];
    
    entry->key = key;
    entry->value = value;
    entry->last_seen = vfm_get_time();
}

// Bounds checking macro
#define BOUNDS_CHECK(vm, offset, len) \
    do { \
        if (VFM_UNLIKELY((offset) + (len) > (vm)->hot.packet_len)) { \
            (vm)->hot.error = VFM_ERROR_BOUNDS; \
            return VFM_ERROR_BOUNDS; \
        } \
    } while(0)

// Stack operations
#define STACK_PUSH(vm, value) \
    do { \
        if (VFM_UNLIKELY((vm)->hot.sp >= (vm)->stack_size - 1)) { \
            (vm)->hot.error = VFM_ERROR_STACK_OVERFLOW; \
            return VFM_ERROR_STACK_OVERFLOW; \
        } \
        (vm)->stack[++(vm)->hot.sp] = (value); \
    } while(0)

#define STACK_POP(vm, var) \
    do { \
        if (VFM_UNLIKELY((vm)->hot.sp == 0)) { \
            (vm)->hot.error = VFM_ERROR_STACK_UNDERFLOW; \
            return VFM_ERROR_STACK_UNDERFLOW; \
        } \
        (var) = (vm)->stack[(vm)->hot.sp--]; \
    } while(0)

#define STACK_TOP(vm) ((vm)->stack[(vm)->hot.sp])

// Core VM implementation
vfm_state_t* vfm_create(void) {
    vfm_state_t *vm = calloc(1, sizeof(vfm_state_t));
    if (!vm) return NULL;
    
    // Allocate stack with proper alignment
    vm->stack_size = VFM_MAX_STACK;
    vm->stack = VFM_ALIGNED_ALLOC(16, vm->stack_size * sizeof(uint64_t));
    if (!vm->stack) {
        free(vm);
        return NULL;
    }
    
    // Initialize execution limits
    vm->hot.insn_limit = VFM_MAX_INSN;
    vm->hot.sp = 0;  // Stack starts empty
    
    // Enable optimizations by default
    vfm_enable_optimizations(vm);
    
    return vm;
}

void vfm_destroy(vfm_state_t *vm) {
    if (!vm) return;
    
    if (vm->stack) {
        free(vm->stack);
    }
    
    if (vm->flow_table) {
        vfm_flow_table_destroy(vm);
    }
    
    free(vm);
}

int vfm_load_program(vfm_state_t *vm, const uint8_t *program, uint32_t len) {
    if (!vm || !program) return VFM_ERROR_INVALID_PROGRAM;
    
    if (len > VFM_MAX_PROGRAM_SIZE) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    // Verify program before loading
    int verify_result = vfm_verify(program, len);
    if (verify_result != VFM_SUCCESS) {
        return verify_result;
    }
    
    vm->program = program;
    vm->program_len = len;
    vm->hot.pc = 0;
    vm->hot.insn_count = 0;
    vm->hot.error = VFM_SUCCESS;
    
    return VFM_SUCCESS;
}

// Core execution loop with computed goto for maximum performance
int vfm_execute(vfm_state_t *vm, const uint8_t *packet, uint16_t packet_len) {
    if (!vm || !packet) return VFM_ERROR_INVALID_PROGRAM;
    
    // Set packet data
    vm->packet = packet;
    vm->hot.packet_len = packet_len;
    vm->hot.pc = 0;
    vm->hot.insn_count = 0;
    vm->hot.sp = 0;  // Reset stack
    vm->hot.error = VFM_SUCCESS;
    
    // Computed goto dispatch table for maximum performance
    static const void *dispatch[] = {
        [VFM_LD8]       = &&op_ld8,
        [VFM_LD16]      = &&op_ld16,
        [VFM_LD32]      = &&op_ld32,
        [VFM_LD64]      = &&op_ld64,
        [VFM_PUSH]      = &&op_push,
        [VFM_POP]       = &&op_pop,
        [VFM_DUP]       = &&op_dup,
        [VFM_SWAP]      = &&op_swap,
        [VFM_ADD]       = &&op_add,
        [VFM_SUB]       = &&op_sub,
        [VFM_MUL]       = &&op_mul,
        [VFM_DIV]       = &&op_div,
        [VFM_AND]       = &&op_and,
        [VFM_OR]        = &&op_or,
        [VFM_XOR]       = &&op_xor,
        [VFM_SHL]       = &&op_shl,
        [VFM_SHR]       = &&op_shr,
        [VFM_JMP]       = &&op_jmp,
        [VFM_JEQ]       = &&op_jeq,
        [VFM_JNE]       = &&op_jne,
        [VFM_JGT]       = &&op_jgt,
        [VFM_JLT]       = &&op_jlt,
        [VFM_JGE]       = &&op_jge,
        [VFM_JLE]       = &&op_jle,
        [VFM_RET]       = &&op_ret,
        [VFM_HASH5]     = &&op_hash5,
        [VFM_CSUM]      = &&op_csum,
        [VFM_PARSE]     = &&op_parse,
        [VFM_FLOW_LOAD] = &&op_flow_load,
        [VFM_FLOW_STORE]= &&op_flow_store,
        [VFM_NOT]       = &&op_not,
        [VFM_NEG]       = &&op_neg,
        [VFM_MOD]       = &&op_mod,
        [VFM_EQ]        = &&op_eq,
        [VFM_NE]        = &&op_ne,
        [VFM_GT]        = &&op_gt,
        [VFM_LT]        = &&op_lt,
        [VFM_GE]        = &&op_ge,
        [VFM_LE]        = &&op_le
    };
    
    #define NEXT() \
        do { \
            if (VFM_UNLIKELY(++vm->hot.insn_count > vm->hot.insn_limit)) { \
                vm->hot.error = VFM_ERROR_LIMIT; \
                return VFM_ERROR_LIMIT; \
            } \
            if (VFM_UNLIKELY(vm->hot.pc >= vm->program_len)) { \
                vm->hot.error = VFM_ERROR_INVALID_PROGRAM; \
                return VFM_ERROR_INVALID_PROGRAM; \
            } \
            uint8_t opcode = vm->program[vm->hot.pc++]; \
            if (VFM_UNLIKELY(opcode >= VFM_OPCODE_MAX)) { \
                vm->hot.error = VFM_ERROR_INVALID_OPCODE; \
                return VFM_ERROR_INVALID_OPCODE; \
            } \
            goto *dispatch[opcode]; \
        } while(0)
    
    // Start execution
    NEXT();
    
op_ld8:
    {
        uint16_t offset = *(uint16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        BOUNDS_CHECK(vm, offset, 1);
        uint64_t val = vm->packet[offset];
        STACK_PUSH(vm, val);
        NEXT();
    }
    
op_ld16:
    {
        uint16_t offset = *(uint16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        BOUNDS_CHECK(vm, offset, 2);
        uint64_t val = ntohs(*(uint16_t*)(vm->packet + offset));
        STACK_PUSH(vm, val);
        NEXT();
    }
    
op_ld32:
    {
        uint16_t offset = *(uint16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        BOUNDS_CHECK(vm, offset, 4);
        uint64_t val = ntohl(*(uint32_t*)(vm->packet + offset));
        STACK_PUSH(vm, val);
        NEXT();
    }
    
op_ld64:
    {
        uint16_t offset = *(uint16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        BOUNDS_CHECK(vm, offset, 8);
        uint64_t val = ((uint64_t)ntohl(*(uint32_t*)(vm->packet + offset)) << 32) |
                       ntohl(*(uint32_t*)(vm->packet + offset + 4));
        STACK_PUSH(vm, val);
        NEXT();
    }
    
op_push:
    {
        uint64_t val = *(uint64_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 8;
        STACK_PUSH(vm, val);
        NEXT();
    }
    
op_pop:
    {
        uint64_t val;
        STACK_POP(vm, val);
        NEXT();
    }
    
op_dup:
    {
        if (VFM_UNLIKELY(vm->hot.sp == 0)) {
            vm->hot.error = VFM_ERROR_STACK_UNDERFLOW;
            return VFM_ERROR_STACK_UNDERFLOW;
        }
        uint64_t val = STACK_TOP(vm);
        STACK_PUSH(vm, val);
        NEXT();
    }
    
op_swap:
    {
        if (VFM_UNLIKELY(vm->hot.sp < 2)) {
            vm->hot.error = VFM_ERROR_STACK_UNDERFLOW;
            return VFM_ERROR_STACK_UNDERFLOW;
        }
        uint64_t tmp = vm->stack[vm->hot.sp];
        vm->stack[vm->hot.sp] = vm->stack[vm->hot.sp - 1];
        vm->stack[vm->hot.sp - 1] = tmp;
        NEXT();
    }
    
op_add:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, a + b);
        NEXT();
    }
    
op_sub:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, a - b);
        NEXT();
    }
    
op_mul:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, a * b);
        NEXT();
    }
    
op_div:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        if (VFM_UNLIKELY(b == 0)) {
            vm->hot.error = VFM_ERROR_DIVISION_BY_ZERO;
            return VFM_ERROR_DIVISION_BY_ZERO;
        }
        STACK_PUSH(vm, a / b);
        NEXT();
    }
    
op_and:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, a & b);
        NEXT();
    }
    
op_or:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, a | b);
        NEXT();
    }
    
op_xor:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, a ^ b);
        NEXT();
    }
    
op_shl:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, a << (b & 63));  // Limit shift to avoid undefined behavior
        NEXT();
    }
    
op_shr:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, a >> (b & 63));  // Limit shift to avoid undefined behavior
        NEXT();
    }
    
op_jmp:
    {
        int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        vm->hot.pc += offset;
        NEXT();
    }
    
op_jeq:
    {
        int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        if (a == b) vm->hot.pc += offset;
        NEXT();
    }
    
op_jne:
    {
        int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        if (a != b) vm->hot.pc += offset;
        NEXT();
    }
    
op_jgt:
    {
        int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        if (a > b) vm->hot.pc += offset;
        NEXT();
    }
    
op_jlt:
    {
        int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        if (a < b) vm->hot.pc += offset;
        NEXT();
    }
    
op_jge:
    {
        int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        if (a >= b) vm->hot.pc += offset;
        NEXT();
    }
    
op_jle:
    {
        int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
        vm->hot.pc += 2;
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        if (a <= b) vm->hot.pc += offset;
        NEXT();
    }
    
op_ret:
    {
        if (VFM_UNLIKELY(vm->hot.sp == 0)) {
            vm->hot.error = VFM_ERROR_STACK_UNDERFLOW;
            return VFM_ERROR_STACK_UNDERFLOW;
        }
        return (int)STACK_TOP(vm);
    }
    
op_hash5:
    {
        uint64_t hash = hash_5tuple(vm->packet, vm->hot.packet_len);
        STACK_PUSH(vm, hash);
        NEXT();
    }
    
op_csum:
    {
        // Simplified checksum validation placeholder
        STACK_PUSH(vm, 1);  // Always valid for now
        NEXT();
    }
    
op_parse:
    {
        // Simplified header parsing placeholder
        STACK_PUSH(vm, 1);  // Always successful for now
        NEXT();
    }
    
op_flow_load:
    {
        uint64_t key;
        STACK_POP(vm, key);
        uint64_t value = flow_table_get(vm, key);
        STACK_PUSH(vm, value);
        NEXT();
    }
    
op_flow_store:
    {
        uint64_t value, key;
        STACK_POP(vm, value);
        STACK_POP(vm, key);
        flow_table_set(vm, key, value);
        NEXT();
    }
    
op_not:
    {
        uint64_t a;
        STACK_POP(vm, a);
        STACK_PUSH(vm, ~a);
        NEXT();
    }
    
op_neg:
    {
        uint64_t a;
        STACK_POP(vm, a);
        STACK_PUSH(vm, (uint64_t)(-(int64_t)a));
        NEXT();
    }
    
op_mod:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        if (VFM_UNLIKELY(b == 0)) {
            vm->hot.error = VFM_ERROR_DIVISION_BY_ZERO;
            return VFM_ERROR_DIVISION_BY_ZERO;
        }
        STACK_PUSH(vm, a % b);
        NEXT();
    }

op_eq:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, (a == b) ? 1 : 0);
        NEXT();
    }

op_ne:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, (a != b) ? 1 : 0);
        NEXT();
    }

op_gt:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, (a > b) ? 1 : 0);
        NEXT();
    }

op_lt:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, (a < b) ? 1 : 0);
        NEXT();
    }

op_ge:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, (a >= b) ? 1 : 0);
        NEXT();
    }

op_le:
    {
        uint64_t b, a;
        STACK_POP(vm, b);
        STACK_POP(vm, a);
        STACK_PUSH(vm, (a <= b) ? 1 : 0);
        NEXT();
    }
}

// Simple verifier implementation
int vfm_verify(const uint8_t *program, uint32_t len) {
    return vfm_verify_extended(program, len, VFM_MAX_INSN);
}

int vfm_verify_extended(const uint8_t *program, uint32_t len, uint32_t max_instructions) {
    if (!program || len == 0) return VFM_ERROR_INVALID_PROGRAM;
    
    uint32_t pc = 0;
    uint32_t insn_count = 0;
    int32_t stack_depth = 0;
    
    while (pc < len) {
        if (++insn_count > max_instructions) {
            return VFM_ERROR_LIMIT;
        }
        
        if (pc >= len) {
            return VFM_ERROR_INVALID_PROGRAM;
        }
        
        uint8_t opcode = program[pc++];
        
        if (opcode >= VFM_OPCODE_MAX) {
            return VFM_ERROR_INVALID_OPCODE;
        }
        
        uint32_t insn_size = vfm_instruction_size(opcode);
        if (insn_size == 0 || pc + insn_size - 1 > len) {
            return VFM_ERROR_INVALID_PROGRAM;
        }
        
        // Update PC for operands
        pc += insn_size - 1;
        
        // Track stack depth changes
        switch (opcode) {
            case VFM_LD8: case VFM_LD16: case VFM_LD32: case VFM_LD64:
            case VFM_PUSH: case VFM_HASH5: case VFM_CSUM: case VFM_PARSE:
                stack_depth++;
                break;
            case VFM_POP:
                stack_depth--;
                break;
            case VFM_DUP:
                stack_depth++;
                break;
            case VFM_ADD: case VFM_SUB: case VFM_MUL: case VFM_DIV:
            case VFM_AND: case VFM_OR: case VFM_XOR: case VFM_SHL: case VFM_SHR:
            case VFM_JEQ: case VFM_JNE: case VFM_JGT: case VFM_JLT:
            case VFM_JGE: case VFM_JLE: case VFM_MOD:
            case VFM_EQ: case VFM_NE: case VFM_GT: case VFM_LT:
            case VFM_GE: case VFM_LE:
                stack_depth -= 2;
                stack_depth++;
                break;
            case VFM_FLOW_STORE:
                stack_depth -= 2;
                break;
            case VFM_FLOW_LOAD:
                break;  // Pop 1, push 1
            case VFM_RET:
                if (stack_depth < 1) return VFM_ERROR_STACK_UNDERFLOW;
                return VFM_SUCCESS;  // Valid program end
        }
        
        if (stack_depth < 0) {
            return VFM_ERROR_STACK_UNDERFLOW;
        }
        
        if (stack_depth > VFM_MAX_STACK) {
            return VFM_ERROR_STACK_OVERFLOW;
        }
    }
    
    return VFM_ERROR_INVALID_PROGRAM;  // No RET instruction found
}

// Platform optimizations
void vfm_enable_optimizations(vfm_state_t *vm) {
    if (!vm) return;
    
#ifdef VFM_APPLE_SILICON
    vm->hints.use_prefetch = true;
    vm->hints.prefetch_distance = 2;
#else
    vm->hints.use_prefetch = true;
    vm->hints.prefetch_distance = 1;
#endif
    
    vm->hints.use_huge_pages = false;  // Disabled by default
}

// Flow table operations
int vfm_flow_table_init(vfm_state_t *vm, uint32_t size) {
    if (!vm) return VFM_ERROR_INVALID_PROGRAM;
    
    // Round up to power of 2
    size = size ? size : VFM_FLOW_TABLE_SIZE;
    uint32_t real_size = 1;
    while (real_size < size) real_size <<= 1;
    
    vm->flow_table = calloc(real_size, sizeof(vfm_flow_entry_t));
    if (!vm->flow_table) return VFM_ERROR_NO_MEMORY;
    
    vm->flow_table_mask = real_size - 1;
    return VFM_SUCCESS;
}

void vfm_flow_table_destroy(vfm_state_t *vm) {
    if (vm && vm->flow_table) {
        free(vm->flow_table);
        vm->flow_table = NULL;
        vm->flow_table_mask = 0;
    }
}

void vfm_flow_table_clear(vfm_state_t *vm) {
    if (vm && vm->flow_table) {
        memset(vm->flow_table, 0, (vm->flow_table_mask + 1) * sizeof(vfm_flow_entry_t));
    }
}

// Error string conversion
const char* vfm_error_string(vfm_error_t error) {
    switch (error) {
        case VFM_SUCCESS: return "Success";
        case VFM_ERROR_BOUNDS: return "Packet bounds violation";
        case VFM_ERROR_LIMIT: return "Instruction limit exceeded";
        case VFM_ERROR_STACK_OVERFLOW: return "Stack overflow";
        case VFM_ERROR_STACK_UNDERFLOW: return "Stack underflow";
        case VFM_ERROR_INVALID_OPCODE: return "Invalid opcode";
        case VFM_ERROR_DIVISION_BY_ZERO: return "Division by zero";
        case VFM_ERROR_INVALID_PROGRAM: return "Invalid program";
        case VFM_ERROR_NO_MEMORY: return "Out of memory";
        case VFM_ERROR_VERIFICATION_FAILED: return "Program verification failed";
        default: return "Unknown error";
    }
}

// Stub implementations for advanced features
void vfm_disassemble(const uint8_t *program, uint32_t len, char *output, size_t output_size) {
    snprintf(output, output_size, "Disassembly not implemented in single header version");
}

int vfm_to_bpf(const uint8_t *vfm_prog, uint32_t vfm_len, bpf_insn_t *bpf_prog, uint32_t *bpf_len) {
    return VFM_ERROR_INVALID_PROGRAM;  // Not implemented
}

int vfm_to_ebpf(const uint8_t *vfm_prog, uint32_t vfm_len, ebpf_insn_t *ebpf_prog, uint32_t *ebpf_len) {
    return VFM_ERROR_INVALID_PROGRAM;  // Not implemented
}

int vfm_to_cbpf(const uint8_t *vfm_prog, uint32_t vfm_len, bpf_program_t *prog) {
    return VFM_ERROR_INVALID_PROGRAM;  // Not implemented
}

int vfm_to_xdp(const uint8_t *vfm_prog, uint32_t vfm_len, char *c_code, size_t code_size) {
    return VFM_ERROR_INVALID_PROGRAM;  // Not implemented
}

void* vfm_jit_compile_x86_64(const uint8_t *program, uint32_t len) {
    return NULL;  // Not implemented
}

void vfm_jit_free(void *code, size_t size) {
    // Not implemented
}

uint64_t vfm_jit_execute(void *jit_code, const uint8_t *packet, uint16_t packet_len) {
    return 0;  // Not implemented
}

void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len) {
    return NULL;  // Not implemented
}

bool vfm_jit_available_arm64(void) {
    return false;  // Not implemented
}

void vfm_get_stats(const vfm_state_t *vm, vfm_stats_t *stats) {
    if (!vm || !stats) return;
    memset(stats, 0, sizeof(*stats));
}

void vfm_reset_stats(vfm_state_t *vm) {
    // Not implemented
}

int vfm_execute_batch(vfm_state_t *vm, vfm_batch_t *batch) {
    if (!vm || !batch) return VFM_ERROR_INVALID_PROGRAM;
    
    for (uint32_t i = 0; i < batch->count; i++) {
        int result = vfm_execute(vm, batch->packets[i], batch->lengths[i]);
        batch->results[i] = (result > 0) ? 1 : 0;
    }
    
    return VFM_SUCCESS;
}

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

#endif // VFM_IMPLEMENTATION

#endif // VFM_SINGLE_HEADER_H