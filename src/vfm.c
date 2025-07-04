#include "vfm.h"
#include "opcodes.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>

// Platform-specific includes
#ifdef VFM_PLATFORM_MACOS
    #include <mach/mach.h>
    #include <mach/vm_map.h>
#endif

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
        if (VFM_UNLIKELY(vm->hot.sp >= vm->stack_size - 1)) { \
            vm->hot.error = VFM_ERROR_STACK_OVERFLOW; \
            return VFM_ERROR_STACK_OVERFLOW; \
        } \
        vm->stack[++vm->hot.sp] = (val); \
    } while(0)

#define STACK_POP(var) \
    do { \
        if (VFM_UNLIKELY(vm->hot.sp == 0)) { \
            vm->hot.error = VFM_ERROR_STACK_UNDERFLOW; \
            return VFM_ERROR_STACK_UNDERFLOW; \
        } \
        (var) = vm->stack[vm->hot.sp--]; \
    } while(0)

#define STACK_TOP(var) \
    do { \
        if (VFM_UNLIKELY(vm->hot.sp == 0)) { \
            vm->hot.error = VFM_ERROR_STACK_UNDERFLOW; \
            return VFM_ERROR_STACK_UNDERFLOW; \
        } \
        (var) = vm->stack[vm->hot.sp]; \
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
    vm->packet = packet;
    vm->hot.packet_len = packet_len;
    vm->hot.pc = 0;
    vm->hot.sp = 0;
    vm->hot.insn_count = 0;
    vm->hot.error = VFM_SUCCESS;
    
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
        [VFM_MOD]        = &&op_mod
    };
    
    // Dispatch to first instruction
    #define DISPATCH() \
        do { \
            if (VFM_UNLIKELY(vm->hot.pc >= vm->program_len)) { \
                vm->hot.error = VFM_ERROR_INVALID_PROGRAM; \
                return VFM_ERROR_INVALID_PROGRAM; \
            } \
            uint8_t opcode = vm->program[vm->hot.pc++]; \
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
    uint16_t offset = *(uint16_t*)&vm->program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 1);
    uint8_t val = vm->packet[offset];
    STACK_PUSH(val);
    DISPATCH();
}

op_ld16: {
    INSN_LIMIT_CHECK();
    uint16_t offset = *(uint16_t*)&vm->program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 2);
    uint16_t val = ntohs(*(uint16_t*)(vm->packet + offset));
    STACK_PUSH(val);
    DISPATCH();
}

op_ld32: {
    INSN_LIMIT_CHECK();
    uint16_t offset = *(uint16_t*)&vm->program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 4);
    uint32_t val = ntohl(*(uint32_t*)(vm->packet + offset));
    STACK_PUSH(val);
    DISPATCH();
}

op_ld64: {
    INSN_LIMIT_CHECK();
    uint16_t offset = *(uint16_t*)&vm->program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 8);
    uint64_t val = ((uint64_t)ntohl(*(uint32_t*)(vm->packet + offset)) << 32) |
                   ntohl(*(uint32_t*)(vm->packet + offset + 4));
    STACK_PUSH(val);
    DISPATCH();
}

op_push: {
    INSN_LIMIT_CHECK();
    uint64_t val = *(uint64_t*)&vm->program[vm->hot.pc];
    vm->hot.pc += 8;
    STACK_PUSH(val);
    DISPATCH();
}

op_pop: {
    INSN_LIMIT_CHECK();
    uint64_t dummy;
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
    uint64_t tmp = vm->stack[vm->hot.sp];
    vm->stack[vm->hot.sp] = vm->stack[vm->hot.sp - 1];
    vm->stack[vm->hot.sp - 1] = tmp;
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
    vm->hot.pc += 2;
    vm->hot.pc = (uint32_t)((int32_t)vm->hot.pc + offset);
    DISPATCH();
}

op_jeq: {
    INSN_LIMIT_CHECK();
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    uint64_t hash = hash_5tuple(vm->packet, vm->hot.packet_len);
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
}

// VM management functions
vfm_state_t* vfm_create(void) {
    vfm_state_t *vm = aligned_alloc(VFM_CACHE_LINE_SIZE, sizeof(vfm_state_t));
    if (!vm) return NULL;
    
    memset(vm, 0, sizeof(vfm_state_t));
    
    // Allocate stack
    vm->stack = aligned_alloc(16, VFM_MAX_STACK * sizeof(uint64_t));
    if (!vm->stack) {
        free(vm);
        return NULL;
    }
    vm->stack_size = VFM_MAX_STACK;
    
    // Set default limits
    vm->hot.insn_limit = VFM_MAX_INSN;
    
    // Enable platform-specific optimizations
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
    if (!vm || !program || len == 0 || len > VFM_MAX_PROGRAM_SIZE) {
        return VFM_ERROR_INVALID_PROGRAM;
    }
    
    // Verify program first
    int result = vfm_verify(program, len);
    if (result != VFM_SUCCESS) {
        return result;
    }
    
    vm->program = program;
    vm->program_len = len;
    
    return VFM_SUCCESS;
}

void vfm_enable_optimizations(vfm_state_t *vm) {
    if (!vm) return;
    
    // Enable optimizations based on platform
    #ifdef VFM_PLATFORM_MACOS
        vm->hints.use_prefetch = true;
        vm->hints.prefetch_distance = 1;
        #ifdef VFM_APPLE_SILICON
            vm->hints.use_huge_pages = true;
        #endif
    #endif
}

int vfm_flow_table_init(vfm_state_t *vm, uint32_t size) {
    if (!vm || size == 0) return VFM_ERROR_INVALID_PROGRAM;
    
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
        // Use VM_FLAGS_SUPERPAGE_SIZE_2MB for better performance
        vm->flow_table = mmap(NULL, table_size, 
                             PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    #else
        vm->flow_table = aligned_alloc(VFM_CACHE_LINE_SIZE, table_size);
    #endif
    
    if (!vm->flow_table) {
        return VFM_ERROR_NO_MEMORY;
    }
    
    memset(vm->flow_table, 0, table_size);
    vm->flow_table_mask = size - 1;
    
    return VFM_SUCCESS;
}

void vfm_flow_table_destroy(vfm_state_t *vm) {
    if (!vm || !vm->flow_table) return;
    
    size_t table_size = (vm->flow_table_mask + 1) * sizeof(vfm_flow_entry_t);
    
    #ifdef VFM_PLATFORM_MACOS
        munmap(vm->flow_table, table_size);
    #else
        free(vm->flow_table);
    #endif
    
    vm->flow_table = NULL;
    vm->flow_table_mask = 0;
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