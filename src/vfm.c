#include "vfm.h"
#include "../dsl/vflisp/vflisp_types.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/mman.h>

// Platform-specific includes
#ifdef VFM_PLATFORM_MACOS
    #include <mach/mach.h>
    #include <mach/vm_map.h>
#endif

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

// Hash function for IPv6 5-tuple
static VFM_ALWAYS_INLINE uint64_t hash_6tuple(const uint8_t *packet, uint16_t len) {
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

// 128-bit stack operations
#define STACK128_PUSH(val) \
    do { \
        if (VFM_UNLIKELY(vm->sp128 >= vm->stack128_size - 1)) { \
            vm->hot.error = VFM_ERROR_STACK_OVERFLOW; \
            return VFM_ERROR_STACK_OVERFLOW; \
        } \
        vm->stack128[++vm->sp128] = (val); \
    } while(0)

#define STACK128_POP(var) \
    do { \
        if (VFM_UNLIKELY(vm->sp128 == 0)) { \
            vm->hot.error = VFM_ERROR_STACK_UNDERFLOW; \
            return VFM_ERROR_STACK_UNDERFLOW; \
        } \
        (var) = vm->stack128[vm->sp128--]; \
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
    vm->sp128 = 0;  // Reset 128-bit stack pointer
    vm->hot.insn_count = 0;
    vm->hot.error = VFM_SUCCESS;
    
    // Try JIT execution first if available
    if (vm->jit_code) {
        uint64_t result = vfm_jit_execute(vm->jit_code, packet, packet_len);
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

// IPv6 opcode implementations
op_ld128: {
    INSN_LIMIT_CHECK();
    uint16_t offset = *(uint16_t*)&vm->program[vm->hot.pc];
    vm->hot.pc += 2;
    BOUNDS_CHECK(offset, 16);
    vfm_u128_t val = vfm_u128_from_bytes(vm->packet + offset);
    // Push as two 64-bit values for compatibility with existing stack operations
    STACK_PUSH(val.high);  // Push high 64 bits first
    STACK_PUSH(val.low);   // Push low 64 bits second
    DISPATCH();
}

op_push128: {
    INSN_LIMIT_CHECK();
    vfm_u128_t val = vfm_u128_from_bytes(&vm->program[vm->hot.pc]);
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    int16_t offset = *(int16_t*)&vm->program[vm->hot.pc];
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
    uint64_t hash = hash_6tuple(vm->packet, vm->hot.packet_len);
    STACK_PUSH(hash);
    DISPATCH();
}

op_ip_ver: {
    INSN_LIMIT_CHECK();
    // Check IP version field at offset 14 (after Ethernet header)
    if (VFM_UNLIKELY(vm->hot.packet_len < 15)) {
        STACK_PUSH(0);  // Invalid packet
    } else {
        uint8_t version = (vm->packet[14] >> 4) & 0x0F;
        STACK_PUSH((uint64_t)version);
    }
    DISPATCH();
}

op_ipv6_ext: {
    INSN_LIMIT_CHECK();
    uint8_t field_type = vm->program[vm->hot.pc];
    vm->hot.pc += 1;
    
    // Extract IPv6 extension header field value
    uint64_t value = vfl_extract_ipv6_ext_field((vfl_field_type_t)field_type, 
                                                vm->packet, vm->hot.packet_len);
    STACK_PUSH(value);
    DISPATCH();
}
}

// VM management functions
vfm_state_t* vfm_create(void) {
    vfm_state_t *vm = aligned_alloc(VFM_CACHE_LINE_SIZE, sizeof(vfm_state_t));
    if (!vm) return NULL;
    
    memset(vm, 0, sizeof(vfm_state_t));
    
    // Allocate regular stack
    vm->stack = aligned_alloc(16, VFM_MAX_STACK * sizeof(uint64_t));
    if (!vm->stack) {
        free(vm);
        return NULL;
    }
    vm->stack_size = VFM_MAX_STACK;
    
    // Allocate 128-bit stack
    vm->stack128 = aligned_alloc(16, VFM_MAX_STACK * sizeof(vfm_u128_t));
    if (!vm->stack128) {
        free(vm->stack);
        free(vm);
        return NULL;
    }
    vm->stack128_size = VFM_MAX_STACK;
    
    // Set default limits
    vm->hot.insn_limit = VFM_MAX_INSN;
    
    // Enable JIT compilation by default
    vm->jit_enabled = true;
    vm->jit_code = NULL;
    vm->jit_code_size = 0;
    
    // Enable platform-specific optimizations
    vfm_enable_optimizations(vm);
    
    return vm;
}

void vfm_destroy(vfm_state_t *vm) {
    if (!vm) return;
    
    if (vm->stack) {
        free(vm->stack);
    }
    
    if (vm->stack128) {
        free(vm->stack128);
    }
    
    // Clean up JIT code
    if (vm->jit_code) {
        vfm_jit_free(vm->jit_code, vm->jit_code_size);
        vm->jit_code = NULL;
        vm->jit_code_size = 0;
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
    
    // Clean up any existing JIT code
    if (vm->jit_code) {
        vfm_jit_free(vm->jit_code, vm->jit_code_size);
        vm->jit_code = NULL;
        vm->jit_code_size = 0;
    }
    
    vm->program = program;
    vm->program_len = len;
    
    // Check if program contains opcodes that are not JIT compatible
    bool jit_compatible = true;
    for (uint32_t pc = 0; pc < len; ) {
        uint8_t opcode = program[pc];
        
        // Check for opcodes not supported by JIT
        if (opcode == VFM_IP_VER || opcode == VFM_IPV6_EXT || opcode == VFM_HASH6 ||
            opcode == VFM_LD128 || opcode == VFM_PUSH128 || 
            opcode == VFM_EQ128 || opcode == VFM_NE128 ||
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
    
    // Attempt JIT compilation if enabled and compatible
    if (vm->jit_enabled && jit_compatible) {
        #ifdef __aarch64__
        extern bool vfm_jit_available_arm64(void);
        if (vfm_jit_available_arm64()) {
            vm->jit_code = vfm_jit_compile_arm64(program, len);
            if (vm->jit_code) {
                vm->jit_code_size = 4096; // ARM64 JIT uses fixed page size
            }
        }
        #elif defined(__x86_64__)
        vm->jit_code = vfm_jit_compile_x86_64(program, len);
        if (vm->jit_code) {
            vm->jit_code_size = len * 32; // Conservative estimate used in JIT
        }
        #endif
    }
    
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