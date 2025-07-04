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

// VM state structure - optimized for cache locality
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
        
        // Packet bounds (hot for bounds checking)
        uint16_t packet_len;
        uint16_t _pad1;  // Padding for alignment
    } VFM_CACHE_ALIGNED hot;
    
    // Packet data pointer (read-only)
    const uint8_t *packet;
    
    // Stack - aligned for performance
    uint64_t *stack VFM_ALIGNED(16);
    uint32_t stack_size;
    uint32_t _pad2;  // Padding
    
    // Program
    const uint8_t *program;
    uint32_t program_len;
    uint32_t _pad3;  // Padding
    
    // Registers (faster than pure stack) - cache line aligned
    uint64_t regs[16] VFM_CACHE_ALIGNED;
    
    // Flow state table (optional) - for stateful filtering
    vfm_flow_entry_t *flow_table;
    uint32_t flow_table_mask;  // Size - 1 for fast modulo
    uint32_t _pad4;  // Padding
    
    // Platform-specific optimization hints
    struct {
        bool use_prefetch;      // Enable prefetching
        bool use_huge_pages;    // Use huge pages for flow table
        uint8_t prefetch_distance;  // How far ahead to prefetch
        uint8_t _pad[5];        // Padding to 8 bytes
    } hints;
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