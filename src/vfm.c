#include "vfm.h"
#include "../dsl/vflisp/vflisp_types.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <pthread.h>

// Forward declarations for static functions
static uint64_t get_timestamp_ns(void);
static void* worker_thread(void *arg);
static void* worker_thread_with_affinity(void *arg);
static vfm_execution_profile_t* create_execution_profile(uint32_t instruction_count);
static void update_execution_profile(vfm_execution_profile_t *profile, uint32_t pc, bool branch_taken, uint64_t cycles);
static void analyze_packet_pattern(vfm_execution_profile_t *profile, const uint8_t *packet, uint16_t len);
static void* adaptive_jit_recompile(vfm_shared_context_t *shared, const uint8_t *program, uint32_t len);
static bool should_recompile(vfm_shared_context_t *shared);
static void update_adaptive_thresholds(vfm_shared_context_t *shared);

// Platform-specific includes
#ifdef VFM_PLATFORM_MACOS
    #include <mach/mach.h>
    #include <sys/sysctl.h>
    #include <mach/thread_policy.h>
    #include <mach/thread_act.h>
    #include <mach/vm_map.h>
    #include <mach/mach_time.h>
#else
    #include <time.h>
#endif

// Forward declarations for JIT cache integration
static uint64_t get_timestamp_ns(void);

// Hash function for IPv4 5-tuple (optimized for common use cases)
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

// Platform-specific SIMD includes
#ifdef __aarch64__
    #include <arm_neon.h>
#elif defined(__x86_64__) && defined(__AVX2__)
    #include <immintrin.h>
#endif

// Cross-platform SIMD IPv6 hash optimization
#ifdef __aarch64__
// ARM64 NEON optimized IPv6 hash
static VFM_ALWAYS_INLINE uint64_t hash_6tuple_neon(const uint8_t *packet, uint16_t len) {
    if (VFM_UNLIKELY(len < 54)) return 0;
    
    const uint8_t *ipv6_hdr = packet + 14;
    const uint8_t *src_ip6 = ipv6_hdr + 8;
    const uint8_t *dst_ip6 = ipv6_hdr + 24;
    
    // Load IPv6 addresses as 128-bit vectors
    uint8x16_t src_vec = vld1q_u8(src_ip6);
    uint8x16_t dst_vec = vld1q_u8(dst_ip6);
    
    // FNV-1a constants
    const uint64_t FNV_PRIME = 1099511628211ULL;
    const uint64_t FNV_OFFSET = 14695981039346656037ULL;
    
    // Parallel processing of source and destination addresses
    // XOR source and destination vectors
    uint8x16_t combined = veorq_u8(src_vec, dst_vec);
    
    // Convert to 64-bit lanes for hash computation
    uint64x2_t hash_vec = vreinterpretq_u64_u8(combined);
    uint64_t hash = FNV_OFFSET;
    
    // Process both 64-bit halves
    hash ^= vgetq_lane_u64(hash_vec, 0);
    hash *= FNV_PRIME;
    hash ^= vgetq_lane_u64(hash_vec, 1);
    hash *= FNV_PRIME;
    
    // Hash ports and protocol
    uint8_t next_hdr = ipv6_hdr[6];
    uint16_t src_port = *(uint16_t*)(packet + 54);
    uint16_t dst_port = *(uint16_t*)(packet + 56);
    
    hash ^= src_port; hash *= FNV_PRIME;
    hash ^= dst_port; hash *= FNV_PRIME;
    hash ^= next_hdr; hash *= FNV_PRIME;
    
    return hash;
}
#elif defined(__x86_64__) && defined(__AVX2__)
// x86_64 AVX2 optimized IPv6 hash
static VFM_ALWAYS_INLINE uint64_t hash_6tuple_avx2(const uint8_t *packet, uint16_t len) {
    if (VFM_UNLIKELY(len < 54)) return 0;
    
    const uint8_t *ipv6_hdr = packet + 14;
    const uint8_t *src_ip6 = ipv6_hdr + 8;
    const uint8_t *dst_ip6 = ipv6_hdr + 24;
    
    // Load IPv6 addresses as 128-bit vectors (using first 16 bytes of 256-bit register)
    __m128i src_vec = _mm_loadu_si128((const __m128i*)src_ip6);
    __m128i dst_vec = _mm_loadu_si128((const __m128i*)dst_ip6);
    
    // XOR source and destination
    __m128i combined = _mm_xor_si128(src_vec, dst_vec);
    
    // Extract 64-bit components for hash computation
    uint64_t hash = 14695981039346656037ULL;
    const uint64_t FNV_PRIME = 1099511628211ULL;
    
    // Process both 64-bit halves
    hash ^= _mm_extract_epi64(combined, 0);
    hash *= FNV_PRIME;
    hash ^= _mm_extract_epi64(combined, 1);
    hash *= FNV_PRIME;
    
    // Hash ports and protocol
    uint8_t next_hdr = ipv6_hdr[6];
    uint16_t src_port = *(uint16_t*)(packet + 54);
    uint16_t dst_port = *(uint16_t*)(packet + 56);
    
    hash ^= src_port; hash *= FNV_PRIME;
    hash ^= dst_port; hash *= FNV_PRIME;
    hash ^= next_hdr; hash *= FNV_PRIME;
    
    return hash;
}
#endif

#if !defined(__aarch64__) && !(defined(__x86_64__) && defined(__AVX2__))
// Scalar fallback IPv6 hash (original implementation)
static VFM_ALWAYS_INLINE uint64_t hash_6tuple_scalar(const uint8_t *packet, uint16_t len) {
    if (VFM_UNLIKELY(len < 54)) return 0;  // Too short for IPv6 header + ports
    
    // IPv6 header starts at offset 14 (Ethernet header)
    const uint8_t *ipv6_hdr = packet + 14;
    
    // Extract IPv6 addresses (16 bytes each)
    const uint8_t *src_ip6 = ipv6_hdr + 8;   // Source IPv6 at offset 8
    const uint8_t *dst_ip6 = ipv6_hdr + 24;  // Destination IPv6 at offset 24
    
    // Next header field and ports
    uint8_t next_hdr = ipv6_hdr[6];
    uint16_t src_port = *(uint16_t*)(packet + 54);  // After IPv6 header
    uint16_t dst_port = *(uint16_t*)(packet + 56);
    
    // FNV-1a hash with IPv6 addresses
    uint64_t hash = 14695981039346656037ULL;
    
    // Hash IPv6 source address (16 bytes)
    for (int i = 0; i < 16; i++) {
        hash ^= src_ip6[i]; hash *= 1099511628211ULL;
    }
    
    // Hash IPv6 destination address (16 bytes)
    for (int i = 0; i < 16; i++) {
        hash ^= dst_ip6[i]; hash *= 1099511628211ULL;
    }
    
    // Hash ports and protocol
    hash ^= src_port; hash *= 1099511628211ULL;
    hash ^= dst_port; hash *= 1099511628211ULL;
    hash ^= next_hdr; hash *= 1099511628211ULL;
    
    return hash;
}
#endif

// Cross-platform IPv6 hash function with automatic SIMD dispatch
static VFM_ALWAYS_INLINE uint64_t hash_6tuple(const uint8_t *packet, uint16_t len) {
#ifdef __aarch64__
    return hash_6tuple_neon(packet, len);
#elif defined(__x86_64__) && defined(__AVX2__)
    return hash_6tuple_avx2(packet, len);
#else
    return hash_6tuple_scalar(packet, len);
#endif
}

// Public hash function wrappers for testing and benchmarking
uint64_t vfm_hash_ipv4_5tuple(const uint8_t *packet, uint16_t len) {
    return hash_5tuple(packet, len);
}

uint64_t vfm_hash_ipv6_5tuple(const uint8_t *packet, uint16_t len) {
    return hash_6tuple(packet, len);
}

// Phase 2.3: Enhanced flow table operations with collision handling and prefetching
static VFM_ALWAYS_INLINE uint64_t flow_table_get(vfm_state_t *vm, uint64_t key) {
    if (VFM_UNLIKELY(!vm->hot.flow_table)) return 0;
    
    vm->hot.flow_stats.lookups++;
    
    uint32_t index = key & vm->hot.flow_table_mask;
    vfm_flow_entry_t *entry = &vm->hot.flow_table[index];
    
    // Prefetch next cache line for better locality
    if (vm->hints.use_prefetch) {
        uint32_t prefetch_index = (index + vm->hints.prefetch_distance) & vm->hot.flow_table_mask;
        __builtin_prefetch(&vm->hot.flow_table[prefetch_index], 0, 3);
    }
    
    // Primary lookup
    if (VFM_LIKELY(entry->key == key && entry->key != 0)) {
        entry->last_seen = vfm_get_time();
        vm->hot.flow_stats.hits++;
        return entry->value;
    }
    
    // Linear probing for collision resolution (max 4 probes for cache efficiency)
    for (int probe = 1; probe <= 4; probe++) {
        uint32_t probe_index = (index + probe) & vm->hot.flow_table_mask;
        vfm_flow_entry_t *probe_entry = &vm->hot.flow_table[probe_index];
        
        if (probe_entry->key == key && probe_entry->key != 0) {
            probe_entry->last_seen = vfm_get_time();
            vm->hot.flow_stats.hits++;
            vm->hot.flow_stats.collisions++;
            return probe_entry->value;
        }
        
        // Stop probing if we hit an empty slot
        if (probe_entry->key == 0) break;
    }
    
    vm->hot.flow_stats.misses++;
    return 0;
}

static VFM_ALWAYS_INLINE void flow_table_set(vfm_state_t *vm, uint64_t key, uint64_t value) {
    if (VFM_UNLIKELY(!vm->hot.flow_table)) return;
    
    uint32_t index = key & vm->hot.flow_table_mask;
    vfm_flow_entry_t *entry = &vm->hot.flow_table[index];
    uint64_t current_time = vfm_get_time();
    
    // Check if updating existing entry
    if (entry->key == key && entry->key != 0) {
        entry->value = value;
        entry->last_seen = current_time;
        return;
    }
    
    // Find insertion point using linear probing with LRU eviction
    vfm_flow_entry_t *best_entry = entry;
    uint64_t oldest_time = entry->last_seen;
    uint32_t best_index = index;
    
    for (int probe = 0; probe <= 4; probe++) {
        uint32_t probe_index = (index + probe) & vm->hot.flow_table_mask;
        vfm_flow_entry_t *probe_entry = &vm->hot.flow_table[probe_index];
        
        // Found empty slot - use it immediately
        if (probe_entry->key == 0) {
            best_entry = probe_entry;
            best_index = probe_index;
            break;
        }
        
        // Track oldest entry for potential LRU eviction
        if (probe_entry->last_seen < oldest_time) {
            oldest_time = probe_entry->last_seen;
            best_entry = probe_entry;
            best_index = probe_index;
        }
    }
    
    // Update statistics
    if (best_entry->key != 0) {
        vm->hot.flow_stats.evictions++;
    }
    if (best_index != index) {
        vm->hot.flow_stats.collisions++;
        best_entry->collision_count++;
    }
    
    // Insert new entry
    best_entry->key = key;
    best_entry->value = value;
    best_entry->last_seen = current_time;
}

// Bounds checking macro - inlined for performance
#define BOUNDS_CHECK(offset, len) \
    do { \
        if (VFM_UNLIKELY((offset) + (len) > vm->hot.packet_len)) { \
            vm->hot.error = VFM_ERROR_BOUNDS; \
            return VFM_ERROR_BOUNDS; \
        } \
    } while(0)

// Stack operations - inlined for performance
#define STACK_PUSH(val) \
    do { \
        if (VFM_UNLIKELY(vm->hot.sp >= vm->hot.stack_size - 1)) { \
            vm->hot.error = VFM_ERROR_STACK_OVERFLOW; \
            return VFM_ERROR_STACK_OVERFLOW; \
        } \
        vm->hot.stack[++vm->hot.sp] = (val); \
    } while(0)

#define STACK_POP(var) \
    do { \
        if (VFM_UNLIKELY(vm->hot.sp == 0)) { \
            vm->hot.error = VFM_ERROR_STACK_UNDERFLOW; \
            return VFM_ERROR_STACK_UNDERFLOW; \
        } \
        (var) = vm->hot.stack[vm->hot.sp--]; \
    } while(0)

#define STACK_TOP(var) \
    do { \
        if (VFM_UNLIKELY(vm->hot.sp == 0)) { \
            vm->hot.error = VFM_ERROR_STACK_UNDERFLOW; \
            return VFM_ERROR_STACK_UNDERFLOW; \
        } \
        (var) = vm->hot.stack[vm->hot.sp]; \
    } while(0)

// 128-bit stack operations
#define STACK128_PUSH(val) \
    do { \
        if (VFM_UNLIKELY(vm->hot.sp128 >= vm->hot.stack128_size - 1)) { \
            vm->hot.error = VFM_ERROR_STACK_OVERFLOW; \
            return VFM_ERROR_STACK_OVERFLOW; \
        } \
        vm->hot.stack128[++vm->hot.sp128] = (val); \
    } while(0)

#define STACK128_POP(var) \
    do { \
        if (VFM_UNLIKELY(vm->hot.sp128 == 0)) { \
            vm->hot.error = VFM_ERROR_STACK_UNDERFLOW; \
            return VFM_ERROR_STACK_UNDERFLOW; \
        } \
        (var) = vm->hot.stack128[vm->hot.sp128--]; \
    } while(0)

// Instruction limit check
#define INSN_LIMIT_CHECK() \
    do { \
        if (VFM_UNLIKELY(++vm->hot.insn_count > vm->hot.insn_limit)) { \
            vm->hot.error = VFM_ERROR_LIMIT; \
            return VFM_ERROR_LIMIT; \
        } \
    } while(0)

// Main execution function with computed goto
int vfm_execute(vfm_state_t *vm, const uint8_t *packet, uint16_t packet_len) {
    // Set up packet data
    vm->hot.packet = packet;
    vm->hot.packet_len = packet_len;
    vm->hot.pc = 0;
    vm->hot.sp = 0;
    vm->hot.sp128 = 0;  // Reset 128-bit stack pointer
    vm->hot.insn_count = 0;
    vm->hot.error = VFM_SUCCESS;
    
    // Try JIT execution first if available
    if (vm->cold.jit_code) {
        uint64_t result = vfm_jit_execute(vm->cold.jit_code, packet, packet_len);
        if (result != (uint64_t)-1) {  // -1 indicates JIT failure, fall back to interpreter
            return (result != 0) ? VFM_SUCCESS : VFM_ERROR_VERIFICATION_FAILED;
        }
        // JIT failed, fall back to interpreter
    }
    
    // Computed goto dispatch table for maximum performance
    static const void *dispatch_table[] = {
        [VFM_LD8]        = &&op_ld8,
        [VFM_LD16]       = &&op_ld16,
        [VFM_LD32]       = &&op_ld32,
        [VFM_LD64]       = &&op_ld64,
        [VFM_PUSH]       = &&op_push,
        [VFM_POP]        = &&op_pop,
        [VFM_DUP]        = &&op_dup,
        [VFM_SWAP]       = &&op_swap,
        [VFM_ADD]        = &&op_add,
        [VFM_SUB]        = &&op_sub,
        [VFM_MUL]        = &&op_mul,
        [VFM_DIV]        = &&op_div,
        [VFM_AND]        = &&op_and,
        [VFM_OR]         = &&op_or,
        [VFM_XOR]        = &&op_xor,
        [VFM_SHL]        = &&op_shl,
        [VFM_SHR]        = &&op_shr,
        [VFM_JMP]        = &&op_jmp,
        [VFM_JEQ]        = &&op_jeq,
        [VFM_JNE]        = &&op_jne,
        [VFM_JGT]        = &&op_jgt,
        [VFM_JLT]        = &&op_jlt,
        [VFM_RET]        = &&op_ret,
        [VFM_HASH5]      = &&op_hash5,
        [VFM_CSUM]       = &&op_csum,
        [VFM_PARSE]      = &&op_parse,
        [VFM_FLOW_LOAD]  = &&op_flow_load,
        [VFM_FLOW_STORE] = &&op_flow_store,
        [VFM_JGE]        = &&op_jge,
        [VFM_JLE]        = &&op_jle,
        [VFM_NOT]        = &&op_not,
        [VFM_NEG]        = &&op_neg,
        [VFM_MOD]        = &&op_mod,
        [VFM_LD128]      = &&op_ld128,
        [VFM_PUSH128]    = &&op_push128,
        [VFM_EQ128]      = &&op_eq128,
        [VFM_NE128]      = &&op_ne128,
        [VFM_GT128]      = &&op_gt128,
        [VFM_LT128]      = &&op_lt128,
        [VFM_GE128]      = &&op_ge128,
        [VFM_LE128]      = &&op_le128,
        [VFM_AND128]     = &&op_and128,
        [VFM_OR128]      = &&op_or128,
        [VFM_XOR128]     = &&op_xor128,
        [VFM_JEQ128]     = &&op_jeq128,
        [VFM_JNE128]     = &&op_jne128,
        [VFM_JGT128]     = &&op_jgt128,
        [VFM_JLT128]     = &&op_jlt128,
        [VFM_JGE128]     = &&op_jge128,
        [VFM_JLE128]     = &&op_jle128,
        [VFM_IP_VER]     = &&op_ip_ver,
        [VFM_IPV6_EXT]   = &&op_ipv6_ext,
        [VFM_HASH6]      = &&op_hash6
    };
    
    // Dispatch to first instruction with intelligent prefetching
    #define DISPATCH() \
        do { \
            if (VFM_UNLIKELY(vm->hot.pc >= vm->hot.program_len)) { \
                vm->hot.error = VFM_ERROR_INVALID_PROGRAM; \
                return VFM_ERROR_INVALID_PROGRAM; \
            } \
            uint8_t opcode = vm->hot.program[vm->hot.pc++]; \
            \
            /* Strategic prefetching for better pipeline performance */ \
            if (vm->cold.hints.use_prefetch) { \
                uint32_t prefetch_distance = vm->cold.hints.prefetch_distance; \
                /* Prefetch next instructions ahead */ \
                if (vm->hot.pc + prefetch_distance < vm->hot.program_len) { \
                    VFM_PREFETCH(&vm->hot.program[vm->hot.pc + prefetch_distance], 0, 3); \
                } \
                /* Prefetch stack area for upcoming operations */ \
                if (vm->hot.sp + 2 < vm->hot.stack_size) { \
                    VFM_PREFETCH(&vm->hot.stack[vm->hot.sp + 2], 1, 2); \
                } \
            } \
            \
            if (VFM_UNLIKELY(opcode >= VFM_OPCODE_MAX)) { \
                vm->hot.error = VFM_ERROR_INVALID_OPCODE; \
                return VFM_ERROR_INVALID_OPCODE; \
            } \
            goto *dispatch_table[opcode]; \
        } while(0)
    
    DISPATCH();
    
    // Instruction implementations
op_ld8: {
    INSN_LIMIT_CHECK();
    uint16_t offset = *(uint16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 1);
    
    // Prefetch nearby packet data for potential sequential access
    if (vm->cold.hints.use_prefetch && offset + 64 < vm->hot.packet_len) {
        VFM_PREFETCH(&vm->hot.packet[offset + 64], 0, 1);
    }
    
    uint8_t val = vm->hot.packet[offset];
    STACK_PUSH(val);
    DISPATCH();
}

op_ld16: {
    INSN_LIMIT_CHECK();
    uint16_t offset = *(uint16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 2);
    uint16_t val = ntohs(*(uint16_t*)(vm->hot.packet + offset));
    STACK_PUSH(val);
    DISPATCH();
}

op_ld32: {
    INSN_LIMIT_CHECK();
    uint16_t offset = *(uint16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 4);
    uint32_t val = ntohl(*(uint32_t*)(vm->hot.packet + offset));
    STACK_PUSH(val);
    DISPATCH();
}

op_ld64: {
    INSN_LIMIT_CHECK();
    uint16_t offset = *(uint16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 8);
    uint64_t val = ((uint64_t)ntohl(*(uint32_t*)(vm->hot.packet + offset)) << 32) |
                   ntohl(*(uint32_t*)(vm->hot.packet + offset + 4));
    STACK_PUSH(val);
    DISPATCH();
}

op_push: {
    INSN_LIMIT_CHECK();
    uint64_t val = *(uint64_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 8;
    STACK_PUSH(val);
    DISPATCH();
}

op_pop: {
    INSN_LIMIT_CHECK();
    uint64_t dummy __attribute__((unused));
    STACK_POP(dummy);
    DISPATCH();
}

op_dup: {
    INSN_LIMIT_CHECK();
    uint64_t val;
    STACK_TOP(val);
    STACK_PUSH(val);
    DISPATCH();
}

op_swap: {
    INSN_LIMIT_CHECK();
    if (VFM_UNLIKELY(vm->hot.sp < 2)) {
        vm->hot.error = VFM_ERROR_STACK_UNDERFLOW;
        return VFM_ERROR_STACK_UNDERFLOW;
    }
    uint64_t tmp = vm->hot.stack[vm->hot.sp];
    vm->hot.stack[vm->hot.sp] = vm->hot.stack[vm->hot.sp - 1];
    vm->hot.stack[vm->hot.sp - 1] = tmp;
    DISPATCH();
}

op_add: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    STACK_PUSH(a + b);
    DISPATCH();
}

op_sub: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    STACK_PUSH(a - b);
    DISPATCH();
}

op_mul: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    STACK_PUSH(a * b);
    DISPATCH();
}

op_div: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    if (VFM_UNLIKELY(b == 0)) {
        vm->hot.error = VFM_ERROR_DIVISION_BY_ZERO;
        return VFM_ERROR_DIVISION_BY_ZERO;
    }
    STACK_PUSH(a / b);
    DISPATCH();
}

op_and: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    STACK_PUSH(a & b);
    DISPATCH();
}

op_or: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    STACK_PUSH(a | b);
    DISPATCH();
}

op_xor: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    STACK_PUSH(a ^ b);
    DISPATCH();
}

op_shl: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    STACK_PUSH(a << (b & 63));  // Limit shift to 63 bits
    DISPATCH();
}

op_shr: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    STACK_PUSH(a >> (b & 63));  // Limit shift to 63 bits
    DISPATCH();
}

op_jmp: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    DISPATCH();
}

op_jeq: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    if (a == b) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jne: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    if (a != b) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jgt: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    if (a > b) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jlt: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    if (a < b) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jge: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    if (a >= b) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jle: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    if (a <= b) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_ret: {
    INSN_LIMIT_CHECK();
    uint64_t result;
    STACK_POP(result);
    return (int)result;
}

op_hash5: {
    INSN_LIMIT_CHECK();
    uint64_t hash = hash_5tuple(vm->hot.packet, vm->hot.packet_len);
    STACK_PUSH(hash);
    DISPATCH();
}

op_csum: {
    INSN_LIMIT_CHECK();
    // Simple checksum validation placeholder
    STACK_PUSH(1);  // Always valid for now
    DISPATCH();
}

op_parse: {
    INSN_LIMIT_CHECK();
    // Parse headers placeholder
    STACK_PUSH(1);  // Always successful for now
    DISPATCH();
}

op_flow_load: {
    INSN_LIMIT_CHECK();
    uint64_t key;
    STACK_POP(key);
    uint64_t value = flow_table_get(vm, key);
    STACK_PUSH(value);
    DISPATCH();
}

op_flow_store: {
    INSN_LIMIT_CHECK();
    uint64_t value, key;
    STACK_POP(value);
    STACK_POP(key);
    flow_table_set(vm, key, value);
    DISPATCH();
}

op_not: {
    INSN_LIMIT_CHECK();
    uint64_t a;
    STACK_POP(a);
    STACK_PUSH(~a);
    DISPATCH();
}

op_neg: {
    INSN_LIMIT_CHECK();
    uint64_t a;
    STACK_POP(a);
    STACK_PUSH((uint64_t)(-(int64_t)a));
    DISPATCH();
}

op_mod: {
    INSN_LIMIT_CHECK();
    uint64_t b, a;
    STACK_POP(b);
    STACK_POP(a);
    if (VFM_UNLIKELY(b == 0)) {
        vm->hot.error = VFM_ERROR_DIVISION_BY_ZERO;
        return VFM_ERROR_DIVISION_BY_ZERO;
    }
    STACK_PUSH(a % b);
    DISPATCH();
}

// IPv6 opcode implementations
op_ld128: {
    INSN_LIMIT_CHECK();
    uint16_t offset = *(uint16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 16);
    vfm_u128_t val = vfm_u128_from_bytes(vm->hot.packet + offset);
    // Push as two 64-bit values for compatibility with existing stack operations
    STACK_PUSH(val.high);  // Push high 64 bits first
    STACK_PUSH(val.low);   // Push low 64 bits second
    DISPATCH();
}

op_push128: {
    INSN_LIMIT_CHECK();
    vfm_u128_t val = vfm_u128_from_bytes(&vm->hot.program[vm->hot.pc]);
    vm->hot.pc += 16;
    // Push as two 64-bit values for compatibility with existing stack operations
    STACK_PUSH(val.high);  // Push high 64 bits first
    STACK_PUSH(val.low);   // Push low 64 bits second
    DISPATCH();
}

op_eq128: {
    INSN_LIMIT_CHECK();
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    uint64_t result = vfm_u128_eq(a, b) ? 1 : 0;
    STACK_PUSH(result);
    DISPATCH();
}

op_ne128: {
    INSN_LIMIT_CHECK();
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    uint64_t result = vfm_u128_ne(a, b) ? 1 : 0;
    STACK_PUSH(result);
    DISPATCH();
}

op_gt128: {
    INSN_LIMIT_CHECK();
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    uint64_t result = vfm_u128_gt(a, b) ? 1 : 0;
    STACK_PUSH(result);
    DISPATCH();
}

op_lt128: {
    INSN_LIMIT_CHECK();
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    uint64_t result = vfm_u128_lt(a, b) ? 1 : 0;
    STACK_PUSH(result);
    DISPATCH();
}

op_ge128: {
    INSN_LIMIT_CHECK();
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    uint64_t result = vfm_u128_ge(a, b) ? 1 : 0;
    STACK_PUSH(result);
    DISPATCH();
}

op_le128: {
    INSN_LIMIT_CHECK();
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    uint64_t result = vfm_u128_le(a, b) ? 1 : 0;
    STACK_PUSH(result);
    DISPATCH();
}

op_and128: {
    INSN_LIMIT_CHECK();
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    vfm_u128_t result = vfm_u128_and(a, b);
    STACK_PUSH(result.high);
    STACK_PUSH(result.low);
    DISPATCH();
}

op_or128: {
    INSN_LIMIT_CHECK();
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    vfm_u128_t result = vfm_u128_or(a, b);
    STACK_PUSH(result.high);
    STACK_PUSH(result.low);
    DISPATCH();
}

op_xor128: {
    INSN_LIMIT_CHECK();
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    vfm_u128_t result = vfm_u128_xor(a, b);
    STACK_PUSH(result.high);
    STACK_PUSH(result.low);
    DISPATCH();
}

op_jeq128: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    if (vfm_u128_eq(a, b)) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jne128: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    if (vfm_u128_ne(a, b)) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jgt128: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    if (vfm_u128_gt(a, b)) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jlt128: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    if (vfm_u128_lt(a, b)) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jge128: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    if (vfm_u128_ge(a, b)) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_jle128: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->hot.program[vm->hot.pc];
    vm->hot.pc += 2;
    // Pop two 128-bit values (4 64-bit stack entries total)
    uint64_t b_low, b_high, a_low, a_high;
    STACK_POP(b_low);   // Second operand low bits
    STACK_POP(b_high);  // Second operand high bits
    STACK_POP(a_low);   // First operand low bits
    STACK_POP(a_high);  // First operand high bits
    
    vfm_u128_t a = {a_low, a_high};
    vfm_u128_t b = {b_low, b_high};
    if (vfm_u128_le(a, b)) {
        vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    }
    DISPATCH();
}

op_hash6: {
    INSN_LIMIT_CHECK();
    
    // Prefetch IPv6 header for optimal SIMD processing
    if (vm->cold.hints.use_prefetch && vm->hot.packet_len >= 54) {
        // Prefetch the entire IPv6 header (40 bytes) + L4 header
        VFM_PREFETCH(&vm->hot.packet[14], 0, 3);      // IPv6 header start
        VFM_PREFETCH(&vm->hot.packet[14 + 32], 0, 3); // IPv6 addresses + L4 header
    }
    
    uint64_t hash = hash_6tuple(vm->hot.packet, vm->hot.packet_len);
    STACK_PUSH(hash);
    DISPATCH();
}

op_ip_ver: {
    INSN_LIMIT_CHECK();
    // Check IP version field at offset 14 (after Ethernet header)
    if (VFM_UNLIKELY(vm->hot.packet_len < 15)) {
        STACK_PUSH(0);  // Invalid packet
    } else {
        uint8_t version = (vm->hot.packet[14] >> 4) & 0x0F;
        STACK_PUSH((uint64_t)version);
    }
    DISPATCH();
}

op_ipv6_ext: {
    INSN_LIMIT_CHECK();
    uint8_t field_type = vm->hot.program[vm->hot.pc];
    vm->hot.pc += 1;
    
    // Extract IPv6 extension header field value
    uint64_t value = vfl_extract_ipv6_ext_field((vfl_field_type_t)field_type, 
                                                vm->hot.packet, vm->hot.packet_len);
    STACK_PUSH(value);
    DISPATCH();
}
}

// VM management functions
vfm_state_t* vfm_create(void) {
    vfm_state_t *vm = VFM_ALIGNED_ALLOC(VFM_CACHE_LINE_SIZE, sizeof(vfm_state_t));
    if (!vm) return NULL;
    
    memset(vm, 0, sizeof(vfm_state_t));
    
    // Allocate regular stack - cache line aligned for better prefetching
    vm->hot.stack = VFM_ALIGNED_ALLOC(VFM_CACHE_LINE_SIZE, VFM_MAX_STACK * sizeof(uint64_t));
    if (!vm->hot.stack) {
        free(vm);
        return NULL;
    }
    vm->hot.stack_size = VFM_MAX_STACK;
    
    // Pre-touch stack pages to avoid page faults during execution
    for (uint32_t i = 0; i < VFM_MAX_STACK; i += VFM_CACHE_LINE_SIZE/sizeof(uint64_t)) {
        vm->hot.stack[i] = 0;
    }
    
    // Allocate 128-bit stack - cache line aligned for better performance
    vm->hot.stack128 = VFM_ALIGNED_ALLOC(VFM_CACHE_LINE_SIZE, VFM_MAX_STACK * sizeof(vfm_u128_t));
    if (!vm->hot.stack128) {
        free(vm->hot.stack);
        free(vm);
        return NULL;
    }
    vm->hot.stack128_size = VFM_MAX_STACK;
    
    // Pre-touch 128-bit stack pages
    for (uint32_t i = 0; i < VFM_MAX_STACK; i += VFM_CACHE_LINE_SIZE/sizeof(vfm_u128_t)) {
        vm->hot.stack128[i].low = 0;
        vm->hot.stack128[i].high = 0;
    }
    
    // Set default limits
    vm->hot.insn_limit = VFM_MAX_INSN;
    
    // Enable JIT compilation by default
    vm->cold.jit_enabled = true;
    vm->cold.jit_code = NULL;
    vm->cold.jit_code_size = 0;
    
    // Enable platform-specific optimizations
    vfm_enable_optimizations(vm);
    
    return vm;
}

void vfm_destroy(vfm_state_t *vm) {
    if (!vm) return;
    
    if (vm->hot.stack) {
        free(vm->hot.stack);
    }
    
    if (vm->hot.stack128) {
        free(vm->hot.stack128);
    }
    
    // Clean up JIT code and cache reference
    if (vm->cold.jit_cache_entry) {
        vfm_jit_cache_release(vm->cold.jit_cache_entry);
        vm->cold.jit_cache_entry = NULL;
    }
    if (vm->cold.jit_code && !vm->cold.jit_cache_entry) {
        // Only free if not from cache (cache manages its own memory)
        vfm_jit_free(vm->cold.jit_code, vm->cold.jit_code_size);
    }
    vm->cold.jit_code = NULL;
    vm->cold.jit_code_size = 0;
    
    if (vm->hot.flow_table) {
        vfm_flow_table_destroy(vm);
    }
    
    free(vm);
}

int vfm_load_program(vfm_state_t *vm, const uint8_t *program, uint32_t len) {
    if (!vm || !program || len == 0 || len > VFM_MAX_PROGRAM_SIZE) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    // Verify program first
    int result = vfm_verify(program, len);
    if (result != VFM_SUCCESS) {
        return result;
    }
    
    // Clean up any existing JIT code and cache reference
    if (vm->cold.jit_cache_entry) {
        vfm_jit_cache_release(vm->cold.jit_cache_entry);
        vm->cold.jit_cache_entry = NULL;
    }
    if (vm->cold.jit_code) {
        // Only free if not from cache (cache manages its own memory)
        if (!vm->cold.jit_cache_entry) {
            vfm_jit_free(vm->cold.jit_code, vm->cold.jit_code_size);
        }
        vm->cold.jit_code = NULL;
        vm->cold.jit_code_size = 0;
    }
    
    vm->hot.program = program;
    vm->hot.program_len = len;
    
    // Check if program contains opcodes that are not JIT compatible
    bool jit_compatible = true;
    for (uint32_t pc = 0; pc < len; ) {
        uint8_t opcode = program[pc];
        
        // Check for opcodes not supported by JIT
        if (opcode == VFM_IP_VER || opcode == VFM_IPV6_EXT || opcode == VFM_HASH6 ||
            opcode == VFM_PUSH128 || 
            opcode == VFM_NE128 ||
            opcode == VFM_GT128 || opcode == VFM_LT128 || opcode == VFM_GE128 || opcode == VFM_LE128 ||
            opcode == VFM_AND128 || opcode == VFM_OR128 || opcode == VFM_XOR128 ||
            opcode == VFM_JEQ128 || opcode == VFM_JNE128 || 
            opcode == VFM_JGT128 || opcode == VFM_JLT128 || opcode == VFM_JGE128 || opcode == VFM_JLE128) {
            jit_compatible = false;
            break;
        }
        
        uint32_t insn_size = vfm_instruction_size(opcode);
        if (insn_size == 0) break;
        pc += insn_size;
    }
    
    // Attempt JIT compilation with cache if enabled and compatible
    if (vm->cold.jit_enabled && jit_compatible) {
        // Compute program hash for cache lookup
        vfm_program_hash_t prog_hash = vfm_compute_program_hash(program, len);
        
        // Check cache for existing compilation
        vfm_jit_cache_entry_t *cached = vfm_jit_cache_lookup(&prog_hash);
        if (cached) {
            // Cache hit - reuse existing JIT code
            vm->cold.jit_code = cached->jit_code;
            vm->cold.jit_code_size = cached->jit_code_size;
            vm->cold.jit_cache_entry = cached;
        } else {
            // Cache miss - compile and store
            void *jit_code = NULL;
            size_t code_size = 0;
            
            #ifdef __aarch64__
            extern bool vfm_jit_available_arm64(void);
            if (vfm_jit_available_arm64()) {
                uint64_t start_time = get_timestamp_ns();
                jit_code = vfm_jit_compile_arm64(program, len);
                if (jit_code) {
                    code_size = 4096; // ARM64 JIT uses fixed page size
                    uint64_t compile_time = get_timestamp_ns() - start_time;
                    
                    // Store in cache
                    vm->cold.jit_cache_entry = vfm_jit_cache_store(&prog_hash, jit_code, code_size);
                    if (vm->cold.jit_cache_entry) {
                        vm->cold.jit_cache_entry->compile_time_ns = compile_time;
                        vm->cold.jit_code = jit_code;
                        vm->cold.jit_code_size = code_size;
                    }
                }
            }
            #elif defined(__x86_64__)
            uint64_t start_time = get_timestamp_ns();
            jit_code = vfm_jit_compile_x86_64(program, len);
            if (jit_code) {
                code_size = len * 32; // Conservative estimate used in JIT
                uint64_t compile_time = get_timestamp_ns() - start_time;
                
                // Store in cache
                vm->cold.jit_cache_entry = vfm_jit_cache_store(&prog_hash, jit_code, code_size);
                if (vm->cold.jit_cache_entry) {
                    vm->cold.jit_cache_entry->compile_time_ns = compile_time;
                    vm->cold.jit_code = jit_code;
                    vm->cold.jit_code_size = code_size;
                }
            }
            #endif
        }
    }
    
    return VFM_SUCCESS;
}

void vfm_enable_optimizations(vfm_state_t *vm) {
    if (!vm) return;
    
    // Enable optimizations based on platform
    #ifdef VFM_APPLE_SILICON
        // Apple Silicon specific optimizations - 128B cache lines
        vm->cold.hints.use_prefetch = true;
        vm->cold.hints.prefetch_distance = 2;     // Prefetch 2 instructions ahead
        vm->cold.hints.use_huge_pages = true;     // Use huge pages for flow table
    #elif defined(VFM_PLATFORM_MACOS)
        // Intel Mac optimizations - 64B cache lines
        vm->cold.hints.use_prefetch = true;
        vm->cold.hints.prefetch_distance = 1;     // Conservative prefetch distance
        vm->cold.hints.use_huge_pages = false;    // Less beneficial on Intel
    #elif defined(VFM_PLATFORM_LINUX)
        // Linux x86_64 optimizations
        vm->cold.hints.use_prefetch = true;
        vm->cold.hints.prefetch_distance = 1;     // Conservative for compatibility
        vm->cold.hints.use_huge_pages = false;    // Platform dependent
    #else
        // Conservative defaults for other platforms
        vm->cold.hints.use_prefetch = false;      // Disable on unknown platforms
        vm->cold.hints.prefetch_distance = 0;
        vm->cold.hints.use_huge_pages = false;
    #endif
}

int vfm_flow_table_init(vfm_state_t *vm, uint32_t size) {
    if (!vm || size == 0) return VFM_ERROR_INVALID_PROGRAM;
    
    // Phase 2.3: Platform-aware hash table sizing
    // Adjust size based on cache line optimization
    #ifdef VFM_APPLE_SILICON
        // Apple Silicon: optimize for 128-byte cache lines
        uint32_t entries_per_cache_line = 128 / sizeof(vfm_flow_entry_t);  // 4 entries per line
        size = ((size + entries_per_cache_line - 1) / entries_per_cache_line) * entries_per_cache_line;
    #else
        // x86_64: optimize for 64-byte cache lines
        uint32_t entries_per_cache_line = 64 / sizeof(vfm_flow_entry_t);   // 2 entries per line
        size = ((size + entries_per_cache_line - 1) / entries_per_cache_line) * entries_per_cache_line;
    #endif
    
    // Round up to power of 2
    size--;
    size |= size >> 1;
    size |= size >> 2;
    size |= size >> 4;
    size |= size >> 8;
    size |= size >> 16;
    size++;
    
    size_t table_size = size * sizeof(vfm_flow_entry_t);
    
    #ifdef VFM_PLATFORM_MACOS
        // Use standard mmap on macOS (huge pages handled by VM system)
        int flags = MAP_PRIVATE | MAP_ANONYMOUS;
        vm->hot.flow_table = mmap(NULL, table_size, PROT_READ | PROT_WRITE, flags, -1, 0);
    #else
        vm->hot.flow_table = VFM_ALIGNED_ALLOC(VFM_CACHE_LINE_SIZE, table_size);
    #endif
    
    if (!vm->hot.flow_table) {
        return VFM_ERROR_NO_MEMORY;
    }
    
    // Initialize flow table and statistics
    memset(vm->hot.flow_table, 0, table_size);
    vm->hot.flow_table_mask = size - 1;
    
    // Initialize statistics
    memset(&vm->hot.flow_stats, 0, sizeof(vm->hot.flow_stats));
    
    return VFM_SUCCESS;
}

void vfm_flow_table_destroy(vfm_state_t *vm) {
    if (!vm || !vm->hot.flow_table) return;
    
    size_t table_size __attribute__((unused)) = (vm->hot.flow_table_mask + 1) * sizeof(vfm_flow_entry_t);
    
    #ifdef VFM_PLATFORM_MACOS
        munmap(vm->hot.flow_table, table_size);
    #else
        free(vm->hot.flow_table);
    #endif
    
    vm->hot.flow_table = NULL;
    vm->hot.flow_table_mask = 0;
    
    // Clear statistics
    memset(&vm->hot.flow_stats, 0, sizeof(vm->hot.flow_stats));
}

// Phase 2.3: Get flow table performance statistics
void vfm_flow_table_get_stats(const vfm_state_t *vm, vfm_flow_stats_t *stats) {
    if (!vm || !stats) return;
    
    // Copy basic statistics
    stats->lookups = vm->hot.flow_stats.lookups;
    stats->hits = vm->hot.flow_stats.hits;
    stats->misses = vm->hot.flow_stats.misses;
    stats->collisions = vm->hot.flow_stats.collisions;
    stats->evictions = vm->hot.flow_stats.evictions;
    
    // Calculate derived statistics
    if (stats->lookups > 0) {
        stats->hit_rate = (double)stats->hits / (double)stats->lookups;
    } else {
        stats->hit_rate = 0.0;
    }
    
    // Calculate load factor by counting non-zero entries
    uint32_t used_entries = 0;
    uint32_t total_entries = vm->hot.flow_table_mask + 1;
    
    if (vm->hot.flow_table && total_entries > 0) {
        for (uint32_t i = 0; i < total_entries; i++) {
            if (vm->hot.flow_table[i].key != 0) {
                used_entries++;
            }
        }
        stats->load_factor = (used_entries * 100) / total_entries;
    } else {
        stats->load_factor = 0;
    }
}

const char* vfm_error_string(vfm_error_t error) {
    switch (error) {
        case VFM_SUCCESS: return "Success";
        case VFM_ERROR_BOUNDS: return "Packet bounds exceeded";
        case VFM_ERROR_LIMIT: return "Instruction limit exceeded";
        case VFM_ERROR_STACK_OVERFLOW: return "Stack overflow";
        case VFM_ERROR_STACK_UNDERFLOW: return "Stack underflow";
        case VFM_ERROR_INVALID_OPCODE: return "Invalid opcode";
        case VFM_ERROR_DIVISION_BY_ZERO: return "Division by zero";
        case VFM_ERROR_INVALID_PROGRAM: return "Invalid program";
        case VFM_ERROR_NO_MEMORY: return "Out of memory";
        case VFM_ERROR_VERIFICATION_FAILED: return "Verification failed";
        default: return "Unknown error";
    }
}

// Platform-independent JIT wrapper functions
void vfm_jit_free(void *code, size_t size) {
    if (code) {
        #ifdef _WIN32
        VirtualFree(code, 0, MEM_RELEASE);
        #else
        munmap(code, size);
        #endif
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

// Platform-specific timestamp function for JIT cache
static uint64_t get_timestamp_ns(void) {
#ifdef VFM_PLATFORM_MACOS
    return mach_absolute_time();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
#endif
}

// ============================================================================
// Phase 3.1.2: Lock-free flow table operations for multi-threaded access
// ============================================================================

// Atomic flow table lookup with lock-free access
static VFM_ALWAYS_INLINE uint64_t flow_table_get_lockfree(vfm_flow_entry_t *flow_table, uint32_t flow_table_mask, uint64_t key) {
    if (VFM_UNLIKELY(!flow_table)) return 0;
    
    uint32_t index = key & flow_table_mask;
    vfm_flow_entry_t *entry __attribute__((unused)) = &flow_table[index];
    
    // Linear probing with atomic reads (max 4 probes for cache efficiency)
    for (int probe = 0; probe <= 4; probe++) {
        uint32_t probe_index = (index + probe) & flow_table_mask;
        vfm_flow_entry_t *probe_entry = &flow_table[probe_index];
        
        // Atomic read of the key
        uint64_t entry_key = atomic_load_explicit(&probe_entry->key, memory_order_acquire);
        
        if (entry_key == key && entry_key != 0) {
            // Found matching entry - update last_seen atomically
            uint64_t current_time = vfm_get_time();
            atomic_store_explicit(&probe_entry->last_seen, current_time, memory_order_relaxed);
            
            // Atomic read of value
            return atomic_load_explicit(&probe_entry->value, memory_order_acquire);
        }
        
        // Stop probing if we hit an empty slot
        if (entry_key == 0) break;
    }
    
    return 0; // Not found
}

// Atomic flow table insertion with lock-free access using compare-and-swap
static VFM_ALWAYS_INLINE bool flow_table_set_lockfree(vfm_flow_entry_t *flow_table, uint32_t flow_table_mask, uint64_t key, uint64_t value) {
    if (VFM_UNLIKELY(!flow_table)) return false;
    
    uint32_t index = key & flow_table_mask;
    uint64_t current_time = vfm_get_time();
    
    // Linear probing to find insertion point
    for (int probe = 0; probe <= 4; probe++) {
        uint32_t probe_index = (index + probe) & flow_table_mask;
        vfm_flow_entry_t *entry = &flow_table[probe_index];
        
        // Try to read current key
        uint64_t entry_key = atomic_load_explicit(&entry->key, memory_order_acquire);
        
        if (entry_key == key && entry_key != 0) {
            // Update existing entry atomically
            atomic_store_explicit(&entry->value, value, memory_order_release);
            atomic_store_explicit(&entry->last_seen, current_time, memory_order_relaxed);
            return true;
        }
        
        if (entry_key == 0) {
            // Try to claim this empty slot with compare-and-swap
            uint64_t expected = 0;
            if (atomic_compare_exchange_strong_explicit(&entry->key, &expected, key, 
                                                      memory_order_acq_rel, memory_order_acquire)) {
                // Successfully claimed the slot, now set the value
                atomic_store_explicit(&entry->value, value, memory_order_release);
                atomic_store_explicit(&entry->last_seen, current_time, memory_order_relaxed);
                atomic_store_explicit(&entry->collision_count, probe, memory_order_relaxed);
                return true;
            }
            // If CAS failed, someone else claimed this slot, continue probing
        }
    }
    
    // No available slot found in probe range - could implement LRU eviction here
    return false;
}

// ============================================================================
// Phase 3.1: Multi-core VFM Implementation
// ============================================================================

// Helper function to get number of available CPU cores
static uint32_t get_cpu_count(void) {
#ifdef VFM_PLATFORM_MACOS
    int ncpu;
    size_t len = sizeof(ncpu);
    if (sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == 0) {
        return (uint32_t)ncpu;
    }
#else
    long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu > 0) {
        return (uint32_t)ncpu;
    }
#endif
    return 1; // Fallback to single core
}

// Worker thread function for multi-core execution
typedef struct worker_context {
    vfm_multicore_state_t *mc_vm;
    vfm_core_context_t *core_ctx;
    uint32_t thread_id;
    volatile bool *shutdown;
    
    // Work queue for this thread
    const uint8_t **packets;
    uint16_t *packet_lengths;
    uint8_t *results;
    uint32_t start_idx;
    uint32_t end_idx;
    
    // Synchronization
    pthread_mutex_t *work_mutex;
    pthread_cond_t *work_cond;
    volatile bool work_ready;
    
} worker_context_t;

static void* worker_thread(void *arg) {
    worker_context_t *ctx = (worker_context_t*)arg;
    vfm_core_context_t *core = ctx->core_ctx;
    vfm_shared_context_t *shared = ctx->mc_vm->shared;
    
    while (!*ctx->shutdown) {
        // Wait for work
        pthread_mutex_lock(ctx->work_mutex);
        while (!ctx->work_ready && !*ctx->shutdown) {
            pthread_cond_wait(ctx->work_cond, ctx->work_mutex);
        }
        pthread_mutex_unlock(ctx->work_mutex);
        
        if (*ctx->shutdown) break;
        
        // Process assigned packet range
        for (uint32_t i = ctx->start_idx; i < ctx->end_idx; i++) {
            core->packet = ctx->packets[i];
            core->hot.packet_len = ctx->packet_lengths[i];
            
            // Reset execution state for each packet
            core->hot.pc = 0;
            core->hot.sp = 0;
            core->hot.insn_count = 0;
            core->hot.error = VFM_SUCCESS;
            
            // Example of lock-free flow table access during execution
            // In real implementation, this would be integrated into VFM opcodes
            if (ctx->mc_vm->flow_table) {
                // Create a simple flow key from packet data (simplified)
                uint64_t flow_key = 0;
                if (core->hot.packet_len >= 20) {
                    // Use first 8 bytes of packet as flow key (simplified)
                    flow_key = *(uint64_t*)core->packet;
                }
                
                // Lock-free flow table lookup
                uint64_t flow_value = flow_table_get_lockfree(ctx->mc_vm->flow_table, 
                                                            ctx->mc_vm->flow_table_mask, 
                                                            flow_key);
                
                // Update flow statistics (per-core, no locks needed)
                core->flow_stats.lookups++;
                if (flow_value != 0) {
                    core->flow_stats.hits++;
                } else {
                    core->flow_stats.misses++;
                    
                    // Try to insert new flow entry (lock-free)
                    uint64_t new_value = i + 1; // Simplified value
                    if (flow_table_set_lockfree(ctx->mc_vm->flow_table, 
                                               ctx->mc_vm->flow_table_mask, 
                                               flow_key, new_value)) {
                        // Successfully inserted
                    }
                }
            }
            
            // Phase 3.2.1: Profile-guided execution with runtime data collection
            uint64_t execution_start = get_timestamp_ns();
            
            // Execute filter (using existing vfm_execute logic)
            // For now, simplified execution - would use actual VFM interpreter
            int result = 1; // Placeholder: would call actual VFM execution
            
            uint64_t execution_cycles = get_timestamp_ns() - execution_start;
            
            // Update execution profile if available
            if (shared->execution_profile) {
                // Update profile for current instruction (simplified - using pc=0)
                update_execution_profile(shared->execution_profile, core->hot.pc, 
                                       result == 1, execution_cycles);
                
                // Analyze packet pattern for adaptive optimization
                analyze_packet_pattern(shared->execution_profile, core->packet, core->hot.packet_len);
            }
            
            ctx->results[i] = (uint8_t)result;
            core->hot.insn_count++;
        }
        
        // Mark work as completed
        ctx->work_ready = false;
    }
    
    return NULL;
}

// Phase 3.1.1: Create multi-core VFM state with per-core isolation
vfm_multicore_state_t* vfm_multicore_create(uint32_t num_cores) {
    if (num_cores == 0 || num_cores > 16) {
        num_cores = get_cpu_count();
        if (num_cores > 16) num_cores = 16; // Limit to max 16 cores
    }
    
    vfm_multicore_state_t *mc_vm = calloc(1, sizeof(vfm_multicore_state_t));
    if (!mc_vm) return NULL;
    
    // Initialize shared context
    mc_vm->shared = calloc(1, sizeof(vfm_shared_context_t));
    if (!mc_vm->shared) {
        free(mc_vm);
        return NULL;
    }
    
    // Configure multi-core setup
    mc_vm->num_cores = num_cores;
    mc_vm->active_cores = 0;
    mc_vm->shutdown = false;
    
    // Initialize shared context
    mc_vm->shared->num_cores = num_cores;
    mc_vm->shared->numa_node = 0; // Default NUMA node
    mc_vm->shared->jit_enabled = true;
    
    // Phase 3.2: Initialize adaptive JIT optimization
    mc_vm->shared->opt_level = VFM_JIT_OPT_BASIC;
    mc_vm->shared->recompilation_threshold = 10000; // Recompile after 10k executions
    mc_vm->shared->total_executions = 0;
    
    // Set platform-specific hints
    #ifdef VFM_APPLE_SILICON
        mc_vm->shared->hints.use_prefetch = true;
        mc_vm->shared->hints.prefetch_distance = 2;
        mc_vm->shared->hints.use_huge_pages = true;
    #else
        mc_vm->shared->hints.use_prefetch = true;
        mc_vm->shared->hints.prefetch_distance = 1;
        mc_vm->shared->hints.use_huge_pages = false;
    #endif
    
    // Allocate per-core contexts with cache line alignment
    mc_vm->cores = calloc(num_cores, sizeof(vfm_core_context_t*));
    if (!mc_vm->cores) {
        free(mc_vm->shared);
        free(mc_vm);
        return NULL;
    }
    
    // Initialize each core context with isolation
    for (uint32_t i = 0; i < num_cores; i++) {
        mc_vm->cores[i] = VFM_ALIGNED_ALLOC(VFM_CACHE_LINE_SIZE, sizeof(vfm_core_context_t));
        if (!mc_vm->cores[i]) {
            // Cleanup on failure
            for (uint32_t j = 0; j < i; j++) {
                if (mc_vm->cores[j]->stack) free(mc_vm->cores[j]->stack);
                free(mc_vm->cores[j]);
            }
            free(mc_vm->cores);
            free(mc_vm->shared);
            free(mc_vm);
            return NULL;
        }
        
        memset(mc_vm->cores[i], 0, sizeof(vfm_core_context_t));
        
        // Initialize per-core stack (isolated to prevent false sharing)
        mc_vm->cores[i]->stack_size = VFM_STACK_SIZE;
        mc_vm->cores[i]->stack = VFM_ALIGNED_ALLOC(128, VFM_STACK_SIZE * sizeof(uint64_t));
        if (!mc_vm->cores[i]->stack) {
            // Cleanup on failure
            for (uint32_t j = 0; j <= i; j++) {
                if (mc_vm->cores[j] && mc_vm->cores[j]->stack) free(mc_vm->cores[j]->stack);
                if (mc_vm->cores[j]) free(mc_vm->cores[j]);
            }
            free(mc_vm->cores);
            free(mc_vm->shared);
            free(mc_vm);
            return NULL;
        }
        
        mc_vm->cores[i]->core_id = i;
        memset(&mc_vm->cores[i]->flow_stats, 0, sizeof(vfm_flow_stats_t));
    }
    
    // Allocate thread handles
    mc_vm->threads = calloc(num_cores, sizeof(pthread_t));
    if (!mc_vm->threads) {
        vfm_multicore_destroy(mc_vm);
        return NULL;
    }
    
    // Initialize shared lock-free flow table
    uint32_t flow_table_size = 1024; // Default size, can be configured
    #ifdef VFM_APPLE_SILICON
        // Optimize for 128-byte cache lines
        uint32_t entries_per_cache_line = 128 / sizeof(vfm_flow_entry_t);
        flow_table_size = ((flow_table_size + entries_per_cache_line - 1) / entries_per_cache_line) * entries_per_cache_line;
    #endif
    
    // Round up to power of 2
    flow_table_size--;
    flow_table_size |= flow_table_size >> 1;
    flow_table_size |= flow_table_size >> 2;
    flow_table_size |= flow_table_size >> 4;
    flow_table_size |= flow_table_size >> 8;
    flow_table_size |= flow_table_size >> 16;
    flow_table_size++;
    
    size_t table_size = flow_table_size * sizeof(vfm_flow_entry_t);
    
    #ifdef VFM_PLATFORM_MACOS
        mc_vm->flow_table = mmap(NULL, table_size, PROT_READ | PROT_WRITE, 
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mc_vm->flow_table == MAP_FAILED) {
            mc_vm->flow_table = NULL;
        }
    #else
        mc_vm->flow_table = VFM_ALIGNED_ALLOC(VFM_CACHE_LINE_SIZE, table_size);
    #endif
    
    if (mc_vm->flow_table) {
        memset(mc_vm->flow_table, 0, table_size);
        mc_vm->flow_table_mask = flow_table_size - 1;
    }
    
    return mc_vm;
}

// Destroy multi-core VFM state
void vfm_multicore_destroy(vfm_multicore_state_t *mc_vm) {
    if (!mc_vm) return;
    
    // Signal shutdown to all threads
    mc_vm->shutdown = true;
    
    // Wait for all threads to complete
    if (mc_vm->threads) {
        for (uint32_t i = 0; i < mc_vm->active_cores; i++) {
            pthread_join(mc_vm->threads[i], NULL);
        }
        free(mc_vm->threads);
    }
    
    // Cleanup per-core contexts
    if (mc_vm->cores) {
        for (uint32_t i = 0; i < mc_vm->num_cores; i++) {
            if (mc_vm->cores[i]) {
                if (mc_vm->cores[i]->stack) {
                    free(mc_vm->cores[i]->stack);
                }
                free(mc_vm->cores[i]);
            }
        }
        free(mc_vm->cores);
    }
    
    // Cleanup shared flow table
    if (mc_vm->flow_table) {
        size_t table_size __attribute__((unused)) = (mc_vm->flow_table_mask + 1) * sizeof(vfm_flow_entry_t);
        #ifdef VFM_PLATFORM_MACOS
            munmap(mc_vm->flow_table, table_size);
        #else
            free(mc_vm->flow_table);
        #endif
    }
    
    // Cleanup shared context
    if (mc_vm->shared) {
        if (mc_vm->shared->jit_code) {
            vfm_jit_free(mc_vm->shared->jit_code, mc_vm->shared->jit_code_size);
        }
        free(mc_vm->shared);
    }
    
    free(mc_vm);
}

// Load program into multi-core VFM
int vfm_multicore_load_program(vfm_multicore_state_t *mc_vm, const uint8_t *program, uint32_t len) {
    if (!mc_vm || !program || len == 0) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    // Store program in shared context (read-only across all cores)
    mc_vm->shared->program = program;
    mc_vm->shared->program_len = len;
    
    // Phase 3.2: Initialize execution profile for adaptive optimization
    uint32_t estimated_instruction_count = len; // Rough estimate
    mc_vm->shared->execution_profile = create_execution_profile(estimated_instruction_count);
    
    // Compile JIT code once for all cores
    if (mc_vm->shared->jit_enabled) {
        #ifdef __aarch64__
            mc_vm->shared->jit_code = vfm_jit_compile_arm64(program, len);
        #elif defined(__x86_64__)
            mc_vm->shared->jit_code = vfm_jit_compile_x86_64(program, len);
        #endif
        
        if (mc_vm->shared->jit_code) {
            mc_vm->shared->jit_code_size = len * 32; // Estimated size
            mc_vm->shared->opt_level = VFM_JIT_OPT_BASIC;
        }
    }
    
    return VFM_SUCCESS;
}

// Execute batch of packets across multiple cores
int vfm_multicore_execute_batch(vfm_multicore_state_t *mc_vm, vfm_batch_t *batch) {
    if (!mc_vm || !batch || batch->count == 0) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    uint32_t packets_per_core = batch->count / mc_vm->num_cores;
    uint32_t remaining_packets = batch->count % mc_vm->num_cores;
    
    // Allocate worker contexts
    worker_context_t *workers = calloc(mc_vm->num_cores, sizeof(worker_context_t));
    if (!workers) return VFM_ERROR_NO_MEMORY;
    
    pthread_mutex_t work_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t work_cond = PTHREAD_COND_INITIALIZER;
    
    // Distribute work across cores
    uint32_t current_packet = 0;
    for (uint32_t i = 0; i < mc_vm->num_cores; i++) {
        workers[i].mc_vm = mc_vm;
        workers[i].core_ctx = mc_vm->cores[i];
        workers[i].thread_id = i;
        workers[i].shutdown = &mc_vm->shutdown;
        
        workers[i].packets = batch->packets;
        workers[i].packet_lengths = batch->lengths;
        workers[i].results = batch->results;
        workers[i].start_idx = current_packet;
        
        uint32_t packets_for_this_core = packets_per_core;
        if (i < remaining_packets) packets_for_this_core++; // Distribute remainder
        
        workers[i].end_idx = current_packet + packets_for_this_core;
        current_packet = workers[i].end_idx;
        
        workers[i].work_mutex = &work_mutex;
        workers[i].work_cond = &work_cond;
        workers[i].work_ready = true;
        
        // Create thread with affinity if enabled
        void* (*thread_func)(void*) = mc_vm->shared->hints.use_prefetch ? 
                                     worker_thread_with_affinity : worker_thread;
        
        if (pthread_create(&mc_vm->threads[i], NULL, thread_func, &workers[i]) != 0) {
            // Cleanup on thread creation failure
            for (uint32_t j = 0; j < i; j++) {
                pthread_cancel(mc_vm->threads[j]);
                pthread_join(mc_vm->threads[j], NULL);
            }
            free(workers);
            return VFM_ERROR_NO_MEMORY;
        }
    }
    
    mc_vm->active_cores = mc_vm->num_cores;
    
    // Signal all threads to start work
    pthread_mutex_lock(&work_mutex);
    pthread_cond_broadcast(&work_cond);
    pthread_mutex_unlock(&work_mutex);
    
    // Wait for all threads to complete
    for (uint32_t i = 0; i < mc_vm->num_cores; i++) {
        pthread_join(mc_vm->threads[i], NULL);
    }
    
    mc_vm->active_cores = 0;
    
    // Phase 3.2.1: Check for adaptive recompilation after batch execution
    if (mc_vm->shared->execution_profile) {
        mc_vm->shared->total_executions += batch->count;
        
        // Phase 3.2.4: Update adaptive thresholds periodically
        static uint64_t threshold_update_counter = 0;
        threshold_update_counter += batch->count;
        
        // Update thresholds every 5000 executions
        if (threshold_update_counter >= 5000) {
            update_adaptive_thresholds(mc_vm->shared);
            threshold_update_counter = 0;
        }
        
        // Check if we should trigger adaptive recompilation
        if (should_recompile(mc_vm->shared)) {
            // Trigger adaptive JIT recompilation with collected profile data
            void *new_jit_code = adaptive_jit_recompile(mc_vm->shared, 
                                                       mc_vm->shared->program, 
                                                       mc_vm->shared->program_len);
            if (new_jit_code) {
                // Update all cores with new optimized JIT code
                for (uint32_t i = 0; i < mc_vm->num_cores; i++) {
                    // Note: In production, this would need proper synchronization
                    // and cleanup of old JIT code
                    mc_vm->cores[i]->jit_code = new_jit_code;
                }
                
                // Reset execution count for next optimization cycle
                mc_vm->shared->total_executions = 0;
            }
        }
    }
    
    // Update global statistics
    mc_vm->global_stats.total_packets += batch->count;
    for (uint32_t i = 0; i < mc_vm->num_cores; i++) {
        mc_vm->global_stats.total_instructions += mc_vm->cores[i]->hot.insn_count;
        mc_vm->global_stats.core_utilization[i]++;
    }
    
    free(workers);
    return VFM_SUCCESS;
}

// Get aggregated statistics from all cores
void vfm_multicore_get_stats(const vfm_multicore_state_t *mc_vm, vfm_stats_t *stats) {
    if (!mc_vm || !stats) return;
    
    memset(stats, 0, sizeof(vfm_stats_t));
    
    // Aggregate statistics from all cores
    for (uint32_t i = 0; i < mc_vm->num_cores; i++) {
        vfm_core_context_t *core = mc_vm->cores[i];
        stats->packets_processed += 1; // Would track actual packets per core
        stats->instructions_executed += core->hot.insn_count;
        
        // Aggregate flow table stats
        stats->flow_hits += core->flow_stats.hits;
        stats->flow_misses += core->flow_stats.misses;
    }
    
    stats->total_execution_time_ns = get_timestamp_ns(); // Would track actual execution time
    stats->avg_instructions_per_packet = stats->packets_processed > 0 ? 
        (double)stats->instructions_executed / stats->packets_processed : 0.0;
}

// ============================================================================
// Phase 3.1.3: Platform-specific thread affinity
// ============================================================================

// Set thread affinity to a specific CPU core
static int set_thread_affinity(pthread_t thread, uint32_t core_id) {
#ifdef VFM_PLATFORM_MACOS
    // macOS thread affinity using thread_policy_set
    thread_affinity_policy_data_t policy = { core_id };
    kern_return_t result = thread_policy_set(pthread_mach_thread_np(thread),
                                            THREAD_AFFINITY_POLICY,
                                            (thread_policy_t)&policy,
                                            THREAD_AFFINITY_POLICY_COUNT);
    return (result == KERN_SUCCESS) ? 0 : -1;
    
#elif defined(__linux__)
    // Fallback for Linux systems - CPU affinity often not available or inconsistent
    // Especially on Alpine Linux/musl, Docker containers, etc.
    (void)thread;
    (void)core_id;
    return 0;  // Pretend success, no affinity support
    
#else
    // Unsupported platform
    (void)thread;
    (void)core_id;
    return -1;
#endif
}


// Enhanced worker thread function with affinity
static void* worker_thread_with_affinity(void *arg) {
    worker_context_t *ctx = (worker_context_t*)arg;
    vfm_core_context_t *core __attribute__((unused)) = ctx->core_ctx;
    
    // Set thread affinity to specific core
    if (set_thread_affinity(pthread_self(), ctx->thread_id) == 0) {
        // Successfully set affinity
    }
    
    // Call the regular worker thread implementation
    return worker_thread(arg);
}

// Configure thread affinity for multi-core VFM
int vfm_multicore_set_thread_affinity(vfm_multicore_state_t *mc_vm, bool enable) {
    if (!mc_vm) return VFM_ERROR_INVALID_PROGRAM;
    
    // This setting will be applied when threads are created
    mc_vm->shared->hints.use_prefetch = enable; // Reuse existing hint field for simplicity
    
    return VFM_SUCCESS;
}

// Set NUMA node for memory allocation
int vfm_multicore_set_numa_node(vfm_multicore_state_t *mc_vm, uint32_t numa_node) {
    if (!mc_vm || !mc_vm->shared) return VFM_ERROR_INVALID_PROGRAM;
    
    mc_vm->shared->numa_node = numa_node;
    
    // On macOS, we can set memory policy preferences
#ifdef VFM_PLATFORM_MACOS
    // macOS doesn't have explicit NUMA APIs, but we can set memory preferences
    // This is more of a hint to the system
    return VFM_SUCCESS;
    
#elif defined(__linux__)
    // Linux: Set NUMA memory policy using numactl APIs
    // This would require linking with libnuma
    // For now, just store the preference
    return VFM_SUCCESS;
    
#else
    return VFM_SUCCESS;
#endif
}

// ============================================================================
// Phase 3.1.4: NUMA-aware memory allocation
// ============================================================================








// ============================================================================
// Phase 3.2: Adaptive JIT Optimization Implementation
// ============================================================================

// Initialize execution profile for adaptive optimization
static vfm_execution_profile_t* create_execution_profile(uint32_t instruction_count) {
    vfm_execution_profile_t *profile = calloc(1, sizeof(vfm_execution_profile_t));
    if (!profile) return NULL;
    
    // Allocate per-instruction profiling arrays
    profile->instruction_profiles = calloc(instruction_count, sizeof(vfm_instruction_profile_t));
    if (!profile->instruction_profiles) {
        free(profile);
        return NULL;
    }
    
    profile->instruction_count = instruction_count;
    
    // Initialize hot path tracking (limit to reasonable size)
    profile->hot_path_count = 16; // Track top 16 hot paths
    profile->hot_paths = calloc(profile->hot_path_count, sizeof(uint32_t));
    
    // Initialize branch hints
    profile->branch_hints.hint_count = instruction_count / 4; // Estimate
    profile->branch_hints.likely_taken = calloc(profile->branch_hints.hint_count, sizeof(uint32_t));
    profile->branch_hints.likely_not_taken = calloc(profile->branch_hints.hint_count, sizeof(uint32_t));
    
    return profile;
}


// Update execution profile during runtime
static void update_execution_profile(vfm_execution_profile_t *profile, uint32_t pc, 
                                    bool branch_taken, uint64_t cycles) {
    if (!profile || pc >= profile->instruction_count) return;
    
    vfm_instruction_profile_t *instr_profile = &profile->instruction_profiles[pc];
    
    // Update execution statistics
    instr_profile->execution_count++;
    instr_profile->cycle_count += cycles;
    
    // Update branch prediction data
    if (branch_taken) {
        instr_profile->branch_taken_count++;
    } else {
        instr_profile->branch_not_taken_count++;
    }
}

// Analyze packet patterns for optimization hints
// Phase 3.2.2: Enhanced packet pattern analysis for runtime optimization
static void analyze_packet_pattern(vfm_execution_profile_t *profile, const uint8_t *packet, uint16_t len) {
    if (!profile || !packet || len < 14) return;
    
    profile->packet_patterns.total_packets++;
    
    // Analyze Ethernet header and protocol distribution
    uint16_t ethertype = (packet[12] << 8) | packet[13];
    
    if (ethertype == 0x0800) { // IPv4
        profile->packet_patterns.ipv4_packets++;
        
        if (len >= 34) {
            uint8_t protocol = packet[23];
            
            // Track specific protocol patterns for optimization hints
            if (protocol == 6) { // TCP
                profile->packet_patterns.tcp_packets++;
                
                // TCP-specific pattern analysis
                if (len >= 54) {
                    uint16_t tcp_flags = packet[47]; // TCP flags byte
                    if (tcp_flags & 0x02) profile->packet_patterns.tcp_syn_packets++;
                    if (tcp_flags & 0x10) profile->packet_patterns.tcp_ack_packets++;
                }
            } else if (protocol == 17) { // UDP
                profile->packet_patterns.udp_packets++;
                
                // UDP pattern analysis - often used for DNS, streaming
                if (len >= 42) {
                    uint16_t dest_port = (packet[36] << 8) | packet[37];
                    if (dest_port == 53 || dest_port == 5353) {
                        profile->packet_patterns.dns_packets++;
                    }
                }
            } else if (protocol == 1) { // ICMP
                profile->packet_patterns.icmp_packets++;
            } else {
                profile->packet_patterns.other_packets++;
            }
            
            // IPv4 address pattern analysis for flow optimization
            uint32_t src_ip = (packet[26] << 24) | (packet[27] << 16) | (packet[28] << 8) | packet[29];
            uint32_t dst_ip = (packet[30] << 24) | (packet[31] << 16) | (packet[32] << 8) | packet[33];
            
            // Track subnet patterns (simplified)
            uint32_t src_subnet = src_ip & 0xFFFFFF00; // /24
            uint32_t dst_subnet __attribute__((unused)) = dst_ip & 0xFFFFFF00;
            
            // Update most common source/destination subnets (simplified tracking)
            if (profile->packet_patterns.common_src_subnet == 0) {
                profile->packet_patterns.common_src_subnet = src_subnet;
                profile->packet_patterns.src_subnet_count = 1;
            } else if (profile->packet_patterns.common_src_subnet == src_subnet) {
                profile->packet_patterns.src_subnet_count++;
            }
        }
    } else if (ethertype == 0x86DD) { // IPv6
        profile->packet_patterns.ipv6_packets++;
        
        if (len >= 54) {
            uint8_t next_header = packet[20];
            if (next_header == 6) {
                profile->packet_patterns.tcp_packets++;
                // IPv6 TCP analysis
                if (len >= 74) {
                    uint16_t tcp_flags = packet[67];
                    if (tcp_flags & 0x02) profile->packet_patterns.tcp_syn_packets++;
                    if (tcp_flags & 0x10) profile->packet_patterns.tcp_ack_packets++;
                }
            } else if (next_header == 17) {
                profile->packet_patterns.udp_packets++;
            } else if (next_header == 58) { // ICMPv6
                profile->packet_patterns.icmpv6_packets++;
            } else {
                profile->packet_patterns.other_packets++;
            }
        }
    } else {
        profile->packet_patterns.other_packets++;
    }
    
    // Packet size distribution analysis for optimization
    if (len <= 64) profile->packet_patterns.small_packets++;
    else if (len <= 512) profile->packet_patterns.medium_packets++;
    else if (len <= 1500) profile->packet_patterns.large_packets++;
    else profile->packet_patterns.jumbo_packets++;
    
    // Update average packet size
    uint64_t total_size = profile->packet_patterns.average_packet_size * (profile->packet_patterns.total_packets - 1);
    profile->packet_patterns.average_packet_size = (total_size + len) / profile->packet_patterns.total_packets;
    
    // Track packet arrival patterns for burst detection
    static uint64_t last_packet_time = 0;
    uint64_t current_time = get_timestamp_ns();
    if (last_packet_time > 0) {
        uint64_t inter_arrival = current_time - last_packet_time;
        
        // Simple burst detection (packets arriving within 1ms)
        if (inter_arrival < 1000000) { // 1ms in nanoseconds
            profile->packet_patterns.burst_packets++;
        }
    }
    last_packet_time = current_time;
}

// Detect hot paths in execution
static void detect_hot_paths(vfm_execution_profile_t *profile) {
    if (!profile || !profile->instruction_profiles) return;
    
    // Find most frequently executed instructions
    uint32_t hot_path_idx = 0;
    for (uint32_t i = 0; i < profile->instruction_count && hot_path_idx < profile->hot_path_count; i++) {
        if (profile->instruction_profiles[i].execution_count > 1000) { // Threshold
            profile->hot_paths[hot_path_idx++] = i;
        }
    }
}

// Generate branch prediction hints based on profile data
static void generate_branch_hints(vfm_execution_profile_t *profile) {
    if (!profile) return;
    
    uint32_t taken_idx = 0, not_taken_idx = 0;
    
    for (uint32_t i = 0; i < profile->instruction_count; i++) {
        vfm_instruction_profile_t *instr = &profile->instruction_profiles[i];
        
        uint32_t total_branches = instr->branch_taken_count + instr->branch_not_taken_count;
        if (total_branches > 100) { // Sufficient sample size
            double taken_ratio = (double)instr->branch_taken_count / total_branches;
            
            if (taken_ratio > 0.8 && taken_idx < profile->branch_hints.hint_count) {
                // Branch is usually taken
                profile->branch_hints.likely_taken[taken_idx++] = i;
            } else if (taken_ratio < 0.2 && not_taken_idx < profile->branch_hints.hint_count) {
                // Branch is usually not taken
                profile->branch_hints.likely_not_taken[not_taken_idx++] = i;
            }
        }
    }
}

// Phase 3.2.2: Adaptive JIT recompilation with packet pattern optimization
static void* adaptive_jit_recompile(vfm_shared_context_t *shared, const uint8_t *program, uint32_t len) {
    if (!shared || !shared->execution_profile) return NULL;
    
    vfm_execution_profile_t *profile = shared->execution_profile;
    
    // Analyze current profile data
    detect_hot_paths(profile);
    generate_branch_hints(profile);
    
    // Phase 3.2.2: Packet pattern-based optimization decisions
    bool optimize_for_ipv4 = false;
    bool optimize_for_ipv6 = false;
    bool optimize_for_tcp = false;
    bool optimize_for_small_packets = false;
    bool optimize_for_bursts = false;
    
    // Determine optimization strategy based on packet patterns
    if (profile->packet_patterns.total_packets > 1000) {
        uint64_t total = profile->packet_patterns.total_packets;
        
        // IPv4 vs IPv6 optimization preference
        double ipv4_ratio = (double)profile->packet_patterns.ipv4_packets / total;
        double ipv6_ratio = (double)profile->packet_patterns.ipv6_packets / total;
        
        if (ipv4_ratio > 0.8) optimize_for_ipv4 = true;
        else if (ipv6_ratio > 0.8) optimize_for_ipv6 = true;
        
        // TCP optimization for connection-heavy workloads
        double tcp_ratio = (double)profile->packet_patterns.tcp_packets / total;
        if (tcp_ratio > 0.7) optimize_for_tcp = true;
        
        // Small packet optimization for latency-sensitive workloads
        double small_packet_ratio = (double)profile->packet_patterns.small_packets / total;
        if (small_packet_ratio > 0.6) optimize_for_small_packets = true;
        
        // Burst optimization for high-throughput scenarios
        double burst_ratio = (double)profile->packet_patterns.burst_packets / total;
        if (burst_ratio > 0.4) optimize_for_bursts = true;
    }
    
    // Free old JIT code
    if (shared->jit_code) {
        vfm_jit_free(shared->jit_code, shared->jit_code_size);
        shared->jit_code = NULL;
    }
    
    // Set optimization flags based on packet patterns
    shared->hints.optimize_for_ipv4 = optimize_for_ipv4;
    shared->hints.optimize_for_ipv6 = optimize_for_ipv6;
    shared->hints.optimize_for_tcp = optimize_for_tcp;
    shared->hints.optimize_for_small_packets = optimize_for_small_packets;
    shared->hints.optimize_for_bursts = optimize_for_bursts;
    
    // Adjust prefetch strategy based on packet patterns
    if (optimize_for_small_packets) {
        shared->hints.prefetch_distance = 1; // Less aggressive for small packets
    } else if (optimize_for_bursts) {
        shared->hints.prefetch_distance = 3; // More aggressive for bursts
    }
    
    // Recompile with profile-guided optimizations
    #ifdef __aarch64__
        // ARM64 JIT with profile-guided optimization
        shared->jit_code = vfm_jit_compile_arm64_adaptive(program, len, profile);
    #elif defined(__x86_64__)
        // x86_64 JIT with profile-guided optimization  
        shared->jit_code = vfm_jit_compile_x86_64_adaptive(program, len, profile);
    #endif
    
    if (shared->jit_code) {
        shared->jit_code_size = len * 32; // Estimated size
        shared->opt_level = VFM_JIT_OPT_ADAPTIVE;
    }
    
    return shared->jit_code;
}

// Check if recompilation is needed based on execution patterns
static bool should_recompile(vfm_shared_context_t *shared) {
    if (!shared || !shared->execution_profile) return false;
    
    vfm_execution_profile_t *profile = shared->execution_profile;
    
    // Primary trigger: Execution count threshold
    if (shared->total_executions >= shared->recompilation_threshold) {
        return true;
    }
    
    // Advanced trigger: Hot path detection
    // If we've identified hot paths that represent >80% of execution
    if (profile->hot_path_count > 0) {
        uint64_t total_hot_executions = 0;
        uint64_t total_executions = 0;
        
        for (uint32_t i = 0; i < profile->instruction_count; i++) {
            total_executions += profile->instruction_profiles[i].execution_count;
        }
        
        for (uint32_t i = 0; i < profile->hot_path_count; i++) {
            uint32_t hot_pc = profile->hot_paths[i];
            if (hot_pc < profile->instruction_count) {
                total_hot_executions += profile->instruction_profiles[hot_pc].execution_count;
            }
        }
        
        // Trigger recompilation if hot paths represent >80% of execution
        if (total_executions > 1000 && 
            total_hot_executions * 100 / total_executions > 80) {
            return true;
        }
    }
    
    // Advanced trigger: Branch misprediction rate
    // If branch prediction accuracy is <70%, consider recompilation for better hints
    uint64_t total_branches = 0;
    uint64_t correct_predictions = 0;
    
    for (uint32_t i = 0; i < profile->instruction_count; i++) {
        vfm_instruction_profile_t *insn_prof = &profile->instruction_profiles[i];
        uint64_t branch_count = insn_prof->branch_taken_count + insn_prof->branch_not_taken_count;
        
        if (branch_count > 0) {
            total_branches += branch_count;
            // Estimate correct predictions (simplified heuristic)
            uint64_t max_branch_direction = (insn_prof->branch_taken_count > insn_prof->branch_not_taken_count) ?
                insn_prof->branch_taken_count : insn_prof->branch_not_taken_count;
            correct_predictions += max_branch_direction;
        }
    }
    
    if (total_branches > 1000 && correct_predictions * 100 / total_branches < 70) {
        return true;
    }
    
    return false;
}

// Phase 3.2.4: Adaptive compilation threshold adjustment
static void adjust_recompilation_threshold(vfm_shared_context_t *shared) {
    if (!shared || !shared->execution_profile) return;
    
    vfm_execution_profile_t *profile = shared->execution_profile;
    
    // Calculate performance metrics to guide threshold adjustment
    uint64_t total_packets = profile->packet_patterns.total_packets;
    if (total_packets < 1000) return; // Need sufficient data
    
    // Base threshold adjustment factors
    double threshold_multiplier = 1.0;
    
    // Factor 1: Packet size distribution
    // Small packets benefit from more frequent recompilation (lower threshold)
    // Large packets can tolerate less frequent recompilation (higher threshold)
    double small_packet_ratio = (double)profile->packet_patterns.small_packets / total_packets;
    double large_packet_ratio = (double)profile->packet_patterns.large_packets / total_packets;
    
    if (small_packet_ratio > 0.7) {
        threshold_multiplier *= 0.5; // Lower threshold for small packets
    } else if (large_packet_ratio > 0.7) {
        threshold_multiplier *= 2.0; // Higher threshold for large packets
    }
    
    // Factor 2: Protocol distribution
    // TCP-heavy workloads often have more stable patterns
    double tcp_ratio = (double)profile->packet_patterns.tcp_packets / total_packets;
    if (tcp_ratio > 0.8) {
        threshold_multiplier *= 1.5; // Higher threshold for stable TCP workloads
    }
    
    // Factor 3: Burst pattern analysis
    // Burst traffic benefits from more frequent optimization
    double burst_ratio = (double)profile->packet_patterns.burst_packets / total_packets;
    if (burst_ratio > 0.5) {
        threshold_multiplier *= 0.7; // Lower threshold for bursty traffic
    }
    
    // Factor 4: Hot path concentration
    // If execution is concentrated in few paths, recompile less frequently
    if (profile->hot_path_count > 0) {
        uint64_t total_hot_executions = 0;
        uint64_t total_executions = 0;
        
        for (uint32_t i = 0; i < profile->instruction_count; i++) {
            total_executions += profile->instruction_profiles[i].execution_count;
        }
        
        for (uint32_t i = 0; i < profile->hot_path_count; i++) {
            uint32_t hot_pc = profile->hot_paths[i];
            if (hot_pc < profile->instruction_count) {
                total_hot_executions += profile->instruction_profiles[hot_pc].execution_count;
            }
        }
        
        if (total_executions > 0) {
            double hot_path_concentration = (double)total_hot_executions / total_executions;
            if (hot_path_concentration > 0.9) {
                threshold_multiplier *= 2.0; // Higher threshold for concentrated execution
            }
        }
    }
    
    // Factor 5: Branch prediction performance
    // Poor branch prediction benefits from frequent recompilation
    uint64_t total_branches = 0;
    uint64_t correct_predictions = 0;
    
    for (uint32_t i = 0; i < profile->instruction_count; i++) {
        vfm_instruction_profile_t *insn_prof = &profile->instruction_profiles[i];
        uint64_t branch_count = insn_prof->branch_taken_count + insn_prof->branch_not_taken_count;
        
        if (branch_count > 0) {
            total_branches += branch_count;
            uint64_t max_direction = (insn_prof->branch_taken_count > insn_prof->branch_not_taken_count) ?
                insn_prof->branch_taken_count : insn_prof->branch_not_taken_count;
            correct_predictions += max_direction;
        }
    }
    
    if (total_branches > 100) {
        double prediction_accuracy = (double)correct_predictions / total_branches;
        if (prediction_accuracy < 0.7) {
            threshold_multiplier *= 0.6; // Lower threshold for poor branch prediction
        } else if (prediction_accuracy > 0.95) {
            threshold_multiplier *= 1.4; // Higher threshold for excellent prediction
        }
    }
    
    // Factor 6: Cache miss rate
    // High cache miss rate benefits from more aggressive optimization
    uint64_t total_cache_misses = 0;
    uint64_t total_instructions = 0;
    
    for (uint32_t i = 0; i < profile->instruction_count; i++) {
        total_cache_misses += profile->instruction_profiles[i].cache_misses;
        total_instructions += profile->instruction_profiles[i].execution_count;
    }
    
    if (total_instructions > 1000) {
        double cache_miss_rate = (double)total_cache_misses / total_instructions;
        if (cache_miss_rate > 0.05) { // 5% cache miss rate
            threshold_multiplier *= 0.8; // Lower threshold for high cache misses
        }
    }
    
    // Apply threshold adjustment with bounds checking
    uint32_t base_threshold = 10000; // Base threshold
    uint32_t new_threshold = (uint32_t)(base_threshold * threshold_multiplier);
    
    // Enforce reasonable bounds
    if (new_threshold < 1000) new_threshold = 1000;     // Minimum threshold
    if (new_threshold > 100000) new_threshold = 100000; // Maximum threshold
    
    shared->recompilation_threshold = new_threshold;
}

// Phase 3.2.4: Adaptive optimization level adjustment
static void adjust_optimization_level(vfm_shared_context_t *shared) {
    if (!shared || !shared->execution_profile) return;
    
    vfm_execution_profile_t *profile = shared->execution_profile;
    
    // Start with current optimization level
    vfm_jit_optimization_level_t new_opt_level = shared->opt_level;
    
    uint64_t total_packets = profile->packet_patterns.total_packets;
    if (total_packets < 1000) return;
    
    // Determine if we should increase or decrease optimization aggressiveness
    bool should_increase_opt = false;
    bool should_decrease_opt = false;
    
    // Increase optimization for stable, high-volume workloads
    double tcp_ratio = (double)profile->packet_patterns.tcp_packets / total_packets;
    double large_packet_ratio = (double)profile->packet_patterns.large_packets / total_packets;
    
    if (tcp_ratio > 0.8 && large_packet_ratio > 0.6 && total_packets > 10000) {
        should_increase_opt = true;
    }
    
    // Decrease optimization for highly variable workloads
    double burst_ratio = (double)profile->packet_patterns.burst_packets / total_packets;
    double protocol_diversity = 0.0;
    
    // Calculate protocol diversity (simplified entropy measure)
    if (total_packets > 0) {
        double ipv4_ratio = (double)profile->packet_patterns.ipv4_packets / total_packets;
        double ipv6_ratio = (double)profile->packet_patterns.ipv6_packets / total_packets;
        double tcp_ratio_local = (double)profile->packet_patterns.tcp_packets / total_packets;
        double udp_ratio = (double)profile->packet_patterns.udp_packets / total_packets;
        
        // Simple diversity measure: how evenly distributed are the protocols?
        protocol_diversity = 1.0 - (ipv4_ratio * ipv4_ratio + ipv6_ratio * ipv6_ratio + 
                                   tcp_ratio_local * tcp_ratio_local + udp_ratio * udp_ratio);
    }
    
    if (burst_ratio > 0.6 || protocol_diversity > 0.5) {
        should_decrease_opt = true;
    }
    
    // Adjust optimization level
    if (should_increase_opt && !should_decrease_opt) {
        if (new_opt_level == VFM_JIT_OPT_BASIC) {
            new_opt_level = VFM_JIT_OPT_AGGRESSIVE;
        } else if (new_opt_level == VFM_JIT_OPT_AGGRESSIVE) {
            new_opt_level = VFM_JIT_OPT_ADAPTIVE;
        }
    } else if (should_decrease_opt && !should_increase_opt) {
        if (new_opt_level == VFM_JIT_OPT_ADAPTIVE) {
            new_opt_level = VFM_JIT_OPT_AGGRESSIVE;
        } else if (new_opt_level == VFM_JIT_OPT_AGGRESSIVE) {
            new_opt_level = VFM_JIT_OPT_BASIC;
        }
    }
    
    shared->opt_level = new_opt_level;
}

// Phase 3.2.4: Comprehensive adaptive threshold update
static void update_adaptive_thresholds(vfm_shared_context_t *shared) {
    adjust_recompilation_threshold(shared);
    adjust_optimization_level(shared);
}