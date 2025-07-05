# VFM Programming Manual

## Table of Contents

1. [Introduction](#introduction)
2. [Architecture Overview](#architecture-overview)
3. [Getting Started](#getting-started)
4. [Instruction Set Reference](#instruction-set-reference)
5. [Programming Guide](#programming-guide)
6. [API Reference](#api-reference)
7. [Command Line Tools](#command-line-tools)
8. [Performance Optimization](#performance-optimization)
9. [Debugging Techniques](#debugging-techniques)
10. [Best Practices](#best-practices)
11. [Appendix A: Example Programs](#appendix-a-example-programs)
12. [Appendix B: Error Codes](#appendix-b-error-codes)

## Introduction

The Velocity Filter Machine (VFM) is a high-performance packet filtering virtual machine designed to process network packets at line rate. VFM uses a custom bytecode interpreter optimized for packet processing tasks.

### Key Features

- Stack-based virtual machine architecture
- Zero-copy packet access
- Static program verification for safety
- JIT compilation support for x86-64 and ARM64
- Flow table support for stateful filtering
- BPF compilation for kernel integration

### Design Philosophy

VFM prioritizes:
1. **Safety**: All programs are verified before execution
2. **Performance**: Optimized for millions of packets per second
3. **Simplicity**: Minimal instruction set focused on packet processing
4. **Portability**: Cross-platform support with platform-specific optimizations

## Architecture Overview

### Virtual Machine Model

VFM implements a stack-based virtual machine with the following components:

- **Stack**: 64-bit values, maximum depth of 256
- **Program Counter**: Points to current instruction
- **Packet Buffer**: Read-only access to packet data
- **Flow Table**: Optional stateful storage
- **Registers**: Internal use for optimization

### Memory Model

```
+------------------+
|  Program Memory  |  <- Bytecode instructions (read-only)
+------------------+
|      Stack       |  <- Computation stack (read/write)
+------------------+
|  Packet Buffer   |  <- Network packet data (read-only)
+------------------+
|   Flow Table     |  <- Stateful storage (read/write)
+------------------+
```

### Execution Model

1. Programs start at address 0
2. Instructions execute sequentially unless control flow changes
3. Execution terminates on RET instruction
4. Return value is top of stack

## Getting Started

### Installation

```bash
# Build from source
make all

# Run tests
make test

# Install tools (optional)
sudo make install PREFIX=/usr/local
```

### Your First Filter

Create a file `simple_filter.vfm`:

```assembly
; Accept all IPv4 packets
LD16 12         ; Load EtherType at offset 12
PUSH 0x0800     ; IPv4 EtherType
JEQ accept      ; Jump if equal
RET 0           ; Drop non-IPv4

accept:
RET 1           ; Accept IPv4
```

Compile and test:

```bash
# Compile to bytecode
./tools/vfm-asm simple_filter.vfm -o simple_filter.bin

# Disassemble to verify
./tools/vfm-dis simple_filter.bin

# Test with packet capture
./tools/vfm-test simple_filter.bin test_packets.pcap
```

### C Integration

```c
#include "vfm.h"

int main() {
    // Create VM instance
    vfm_state_t *vm = vfm_create();
    
    // Load filter program
    if (vfm_load_program_file(vm, "simple_filter.bin") != VFM_SUCCESS) {
        fprintf(stderr, "Failed to load filter\n");
        return 1;
    }
    
    // Process packet
    uint8_t packet[1500];
    uint16_t packet_len = receive_packet(packet);
    
    int result = vfm_execute(vm, packet, packet_len);
    if (result == 1) {
        // Accept packet
        forward_packet(packet, packet_len);
    } else {
        // Drop packet
    }
    
    vfm_destroy(vm);
    return 0;
}
```

## Instruction Set Reference

### Packet Access Instructions

#### LD8 - Load Byte
```assembly
LD8 offset
```
Loads a single byte from packet at specified offset onto stack.

Example:
```assembly
LD8 23      ; Load IP protocol field
```

#### LD16 - Load 16-bit Word
```assembly
LD16 offset
```
Loads 16-bit value from packet (network byte order) and converts to host order.

Example:
```assembly
LD16 12     ; Load EtherType
LD16 36     ; Load TCP destination port
```

#### LD32 - Load 32-bit Word
```assembly
LD32 offset
```
Loads 32-bit value from packet (network byte order) and converts to host order.

Example:
```assembly
LD32 26     ; Load source IP address
```

#### LD64 - Load 64-bit Word
```assembly
LD64 offset
```
Loads 64-bit value from packet (network byte order) and converts to host order.

### Stack Operations

#### PUSH - Push Immediate
```assembly
PUSH value
```
Pushes 64-bit immediate value onto stack.

Example:
```assembly
PUSH 0x0800     ; Push IPv4 EtherType
PUSH 80         ; Push HTTP port
PUSH -1         ; Push all bits set
```

#### POP - Pop Value
```assembly
POP
```
Removes top value from stack.

Example:
```assembly
PUSH 10
PUSH 20
POP         ; Stack now contains only 10
```

#### DUP - Duplicate Top
```assembly
DUP
```
Duplicates top stack value.

Example:
```assembly
PUSH 42
DUP         ; Stack now contains 42, 42
```

#### SWAP - Swap Top Two
```assembly
SWAP
```
Exchanges top two stack values.

Example:
```assembly
PUSH 10
PUSH 20
SWAP        ; Stack now contains 10, 20 (swapped)
```

### Arithmetic Operations

All arithmetic operations pop two values, perform operation, and push result.

#### ADD - Addition
```assembly
ADD
```
Pops b, pops a, pushes a + b.

Example:
```assembly
PUSH 10
PUSH 5
ADD         ; Result: 15
```

#### SUB - Subtraction
```assembly
SUB
```
Pops b, pops a, pushes a - b.

Example:
```assembly
PUSH 10
PUSH 3
SUB         ; Result: 7
```

#### MUL - Multiplication
```assembly
MUL
```
Pops b, pops a, pushes a * b.

#### DIV - Division
```assembly
DIV
```
Pops b, pops a, pushes a / b. Returns error if b is zero.

#### MOD - Modulo
```assembly
MOD
```
Pops b, pops a, pushes a % b.

### Bitwise Operations

#### AND - Bitwise AND
```assembly
AND
```
Pops two values, pushes bitwise AND.

Example:
```assembly
LD8 47      ; Load TCP flags
PUSH 0x02   ; SYN flag
AND         ; Check if SYN is set
```

#### OR - Bitwise OR
```assembly
OR
```
Pops two values, pushes bitwise OR.

#### XOR - Bitwise XOR
```assembly
XOR
```
Pops two values, pushes bitwise XOR.

#### NOT - Bitwise NOT
```assembly
NOT
```
Pops one value, pushes bitwise NOT.

#### SHL - Shift Left
```assembly
SHL
```
Pops shift count, pops value, pushes value << count.

#### SHR - Shift Right
```assembly
SHR
```
Pops shift count, pops value, pushes value >> count.

### Control Flow

#### JMP - Unconditional Jump
```assembly
JMP offset
```
Jumps to PC + offset (signed 16-bit).

Example:
```assembly
JMP end     ; Jump forward
loop:
    ; ... code ...
    JMP loop    ; Jump backward
end:
```

#### JEQ - Jump if Equal
```assembly
JEQ offset
```
Pops two values, jumps if equal.

Example:
```assembly
LD16 12
PUSH 0x0800
JEQ ipv4_handler
```

#### JNE - Jump if Not Equal
```assembly
JNE offset
```
Pops two values, jumps if not equal.

#### JGT - Jump if Greater Than
```assembly
JGT offset
```
Pops b, pops a, jumps if a > b.

#### JLT - Jump if Less Than
```assembly
JLT offset
```
Pops b, pops a, jumps if a < b.

#### JGE - Jump if Greater or Equal
```assembly
JGE offset
```
Pops b, pops a, jumps if a >= b.

#### JLE - Jump if Less or Equal
```assembly
JLE offset
```
Pops b, pops a, jumps if a <= b.

#### RET - Return
```assembly
RET
```
Terminates execution, returns top of stack as result.

Example:
```assembly
PUSH 1
RET         ; Accept packet
```

### Special Operations

#### HASH5 - Hash 5-Tuple
```assembly
HASH5
```
Computes hash of packet 5-tuple (protocol, src/dst IP, src/dst port).

Example:
```assembly
HASH5           ; Get flow hash
FLOW_LOAD       ; Load counter for this flow
```

#### FLOW_LOAD - Load from Flow Table
```assembly
FLOW_LOAD
```
Pops key, pushes value from flow table (0 if not found).

#### FLOW_STORE - Store to Flow Table
```assembly
FLOW_STORE
```
Pops value, pops key, stores value in flow table.

Example:
```assembly
; Rate limiting example
HASH5           ; Get flow hash
DUP             ; Duplicate for store
FLOW_LOAD       ; Load current count
PUSH 1
ADD             ; Increment
DUP             ; Duplicate for check
SWAP            ; Get hash back on top
SWAP            ; Get value on top
FLOW_STORE      ; Store new count
PUSH 100        ; Rate limit
JGT drop        ; Drop if over limit
```

## Programming Guide

### Basic Packet Filtering

#### Filtering by Protocol

```assembly
; Accept only TCP packets
LD16 12         ; EtherType
PUSH 0x0800     ; IPv4
JNE drop

LD8 23          ; IP Protocol
PUSH 6          ; TCP
JNE drop

RET 1           ; Accept

drop:
RET 0           ; Drop
```

#### Port-Based Filtering

```assembly
; Accept HTTP and HTTPS traffic
LD16 12         ; EtherType
PUSH 0x0800     ; IPv4
JNE drop

LD8 23          ; IP Protocol
PUSH 6          ; TCP
JNE drop

LD16 36         ; Destination port
DUP             ; Duplicate for second check
PUSH 80         ; HTTP
JEQ accept
PUSH 443        ; HTTPS
JEQ accept

drop:
RET 0

accept:
RET 1
```

### Stateful Filtering

#### Connection Tracking

```assembly
; Simple SYN flood detection
LD16 12         ; EtherType
PUSH 0x0800     ; IPv4
JNE accept      ; Not IPv4, accept

LD8 23          ; IP Protocol
PUSH 6          ; TCP
JNE accept      ; Not TCP, accept

LD8 47          ; TCP Flags
PUSH 0x02       ; SYN flag
AND
PUSH 0x02
JNE accept      ; Not SYN, accept

; Count SYNs per source
LD32 26         ; Source IP
DUP             ; Duplicate for store
FLOW_LOAD       ; Get current count
PUSH 1
ADD             ; Increment
DUP             ; Duplicate for comparison
SWAP            ; Get IP back
SWAP            ; Get count on top
FLOW_STORE      ; Store new count

PUSH 10         ; Threshold
JGT drop        ; Too many SYNs

accept:
RET 1

drop:
RET 0
```

### Advanced Techniques

#### Subroutines Using Stack

VFM doesn't have explicit subroutines, but you can simulate them:

```assembly
; Main program
PUSH return1    ; Push return address
JMP check_ipv4
return1:
; ... rest of program ...

check_ipv4:
    LD16 12
    PUSH 0x0800
    JEQ is_ipv4
    PUSH 0      ; Not IPv4
    SWAP        ; Get return address
    JMP 0       ; Jump to return address (dynamic)
is_ipv4:
    PUSH 1      ; Is IPv4
    SWAP        ; Get return address
    JMP 0       ; Jump to return address (dynamic)
```

#### Packet Parsing

```assembly
; Parse and validate IPv4 header
LD16 12         ; EtherType
PUSH 0x0800
JNE invalid

LD8 14          ; Version/IHL
DUP
PUSH 4
SHR             ; Get version
PUSH 4
JNE invalid     ; Not IPv4

PUSH 0x0F
AND             ; Get IHL
PUSH 5
JLT invalid     ; IHL < 5 is invalid
PUSH 15
JGT invalid     ; IHL > 15 is invalid

; Calculate header length
PUSH 4
MUL             ; IHL * 4 = header length

; Validate total length
LD16 16         ; Total length
DUP
PUSH 20         ; Minimum IP packet
JLT invalid

RET 1           ; Valid

invalid:
RET 0
```

## API Reference

### Core Functions

#### vfm_create
```c
vfm_state_t* vfm_create(void);
```
Creates new VM instance.

Returns:
- Pointer to VM state on success
- NULL on failure

Example:
```c
vfm_state_t *vm = vfm_create();
if (!vm) {
    fprintf(stderr, "Failed to create VM\n");
    return -1;
}
```

#### vfm_destroy
```c
void vfm_destroy(vfm_state_t *vm);
```
Destroys VM instance and frees resources.

#### vfm_load_program
```c
int vfm_load_program(vfm_state_t *vm, const uint8_t *program, uint32_t len);
```
Loads bytecode program into VM.

Parameters:
- `vm`: VM instance
- `program`: Bytecode array
- `len`: Program length in bytes

Returns:
- `VFM_SUCCESS` on success
- Error code on failure

#### vfm_load_program_file
```c
int vfm_load_program_file(vfm_state_t *vm, const char *filename);
```
Loads bytecode program from file.

#### vfm_execute
```c
int vfm_execute(vfm_state_t *vm, const uint8_t *packet, uint16_t packet_len);
```
Executes loaded program on packet.

Parameters:
- `vm`: VM instance with loaded program
- `packet`: Packet data
- `packet_len`: Packet length

Returns:
- Program return value on success
- Negative error code on failure

Example:
```c
int result = vfm_execute(vm, packet_data, packet_len);
switch (result) {
    case 1:
        // Accept packet
        break;
    case 0:
        // Drop packet
        break;
    default:
        if (result < 0) {
            // Handle error
            fprintf(stderr, "Execution error: %d\n", result);
        }
}
```

### Flow Table Functions

#### vfm_flow_table_init
```c
int vfm_flow_table_init(vfm_state_t *vm, uint32_t size);
```
Initializes flow table with specified size.

#### vfm_flow_table_clear
```c
void vfm_flow_table_clear(vfm_state_t *vm);
```
Clears all entries from flow table.

### Verification Functions

#### vfm_verify
```c
int vfm_verify(const uint8_t *program, uint32_t len);
```
Verifies program safety before execution.

Returns:
- `VFM_SUCCESS` if program is safe
- Error code indicating verification failure

Example:
```c
uint8_t program[256];
uint32_t len = load_program(program);

if (vfm_verify(program, len) != VFM_SUCCESS) {
    fprintf(stderr, "Program failed verification\n");
    return -1;
}
```

### Compilation Functions

#### vfm_to_bpf
```c
int vfm_to_bpf(const uint8_t *vfm_prog, uint32_t vfm_len,
               bpf_insn_t *bpf_prog, uint32_t *bpf_len);
```
Compiles VFM bytecode to classic BPF.

### Error Codes

```c
#define VFM_SUCCESS                  0
#define VFM_ERROR_NO_MEMORY         -1
#define VFM_ERROR_INVALID_PROGRAM   -2
#define VFM_ERROR_INVALID_OPCODE    -3
#define VFM_ERROR_STACK_OVERFLOW    -4
#define VFM_ERROR_STACK_UNDERFLOW   -5
#define VFM_ERROR_BOUNDS            -6
#define VFM_ERROR_DIVISION_BY_ZERO  -7
#define VFM_ERROR_LIMIT             -8
#define VFM_ERROR_VERIFICATION_FAILED -9
```

## Command Line Tools

### vfm-asm - Assembler

Converts VFM assembly to bytecode.

```bash
vfm-asm [options] input.vfm -o output.bin
```

Options:
- `-o, --output`: Output file (required)
- `-v, --verbose`: Verbose output
- `-h, --help`: Show help

Example:
```bash
# Basic assembly
./tools/vfm-asm filter.vfm -o filter.bin

# Verbose mode
./tools/vfm-asm -v complex_filter.vfm -o complex_filter.bin
```

### vfm-dis - Disassembler

Converts bytecode back to assembly.

```bash
vfm-dis [options] input.bin [output.asm]
```

Options:
- `-a, --addresses`: Show bytecode addresses
- `-x, --hex`: Show hex dump
- `-v, --verbose`: Verbose output
- `-h, --help`: Show help

Example:
```bash
# Basic disassembly
./tools/vfm-dis filter.bin

# With addresses and hex
./tools/vfm-dis -a -x filter.bin filter_debug.asm
```

### vfm-test - Filter Tester

Tests filters against packet captures.

```bash
vfm-test [options] filter.bin packets.pcap
```

Options:
- `-v, --verbose`: Verbose output
- `-s, --stats`: Show statistics
- `-h, --help`: Show help

Example:
```bash
# Test filter
./tools/vfm-test tcp_filter.bin capture.pcap

# With statistics
./tools/vfm-test -s -v ddos_filter.bin attack_trace.pcap
```

## Performance Optimization

### Optimization Techniques

#### 1. Minimize Stack Operations

Bad:
```assembly
PUSH 10
PUSH 20
ADD
PUSH 5
SUB
```

Good:
```assembly
PUSH 10
PUSH 20
ADD
PUSH 5
SUB
```

#### 2. Use Conditional Jumps Efficiently

Bad:
```assembly
LD16 12
PUSH 0x0800
JNE not_ipv4
JMP is_ipv4
not_ipv4:
    RET 0
is_ipv4:
    RET 1
```

Good:
```assembly
LD16 12
PUSH 0x0800
JNE drop
RET 1
drop:
RET 0
```

#### 3. Cache Flow Table Lookups

Bad:
```assembly
HASH5
FLOW_LOAD
; ... some code ...
HASH5
FLOW_LOAD  ; Redundant
```

Good:
```assembly
HASH5
DUP        ; Keep hash on stack
FLOW_LOAD
; ... some code ...
SWAP       ; Get hash back
FLOW_LOAD
```

### JIT Compilation

Enable JIT for maximum performance:

```c
vfm_state_t *vm = vfm_create();
vfm_enable_jit(vm);  // Enable JIT compilation
vfm_load_program_file(vm, "filter.bin");
```

### Benchmarking

```c
#include <time.h>

void benchmark_filter(vfm_state_t *vm, uint8_t *packets[], 
                     uint16_t lengths[], int count) {
    struct timespec start, end;
    
    clock_gettime(CLOCK_MONOTONIC, &start);
    
    for (int i = 0; i < count; i++) {
        vfm_execute(vm, packets[i], lengths[i]);
    }
    
    clock_gettime(CLOCK_MONOTONIC, &end);
    
    double elapsed = (end.tv_sec - start.tv_sec) + 
                    (end.tv_nsec - start.tv_nsec) / 1e9;
    double pps = count / elapsed;
    
    printf("Processed %d packets in %.3f seconds (%.1f Mpps)\n",
           count, elapsed, pps / 1e6);
}
```

## Debugging Techniques

### Using the Disassembler

Always verify compiled bytecode:

```bash
# Compile
./tools/vfm-asm myfilter.vfm -o myfilter.bin

# Verify
./tools/vfm-dis -a -x myfilter.bin
```

### Adding Debug Output

Create debug filters that push intermediate values:

```assembly
; Debug version
LD16 12         ; EtherType
DUP             ; Duplicate for debug
PUSH 0x0800
JNE not_ipv4
POP             ; Remove debug value
RET 1

not_ipv4:
; Top of stack contains actual EtherType
RET 0
```

### Single-Step Execution

Implement a debug executor:

```c
int debug_execute(vfm_state_t *vm, const uint8_t *packet, 
                  uint16_t len) {
    // Save original limit
    uint32_t saved_limit = vm->hot.insn_limit;
    
    // Set limit to 1 for single-step
    vm->hot.insn_limit = 1;
    
    int result;
    uint32_t step = 0;
    
    while ((result = vfm_execute(vm, packet, len)) == VFM_ERROR_LIMIT) {
        printf("Step %u: PC=%u, Stack depth=%u\n", 
               step++, vm->pc, vm->sp);
        
        // Print stack
        for (uint32_t i = 0; i <= vm->sp; i++) {
            printf("  [%u] = %llu\n", i, vm->stack[i]);
        }
        
        // Reset for next instruction
        vm->hot.insn_count = 0;
        vm->hot.insn_limit = 1;
    }
    
    // Restore limit
    vm->hot.insn_limit = saved_limit;
    return result;
}
```

## Best Practices

### 1. Always Verify Programs

```c
if (vfm_verify(program, len) != VFM_SUCCESS) {
    // Reject untrusted program
    return -1;
}
```

### 2. Handle All Error Cases

```c
int result = vfm_execute(vm, packet, len);
if (result < 0) {
    switch (result) {
        case VFM_ERROR_BOUNDS:
            log_error("Packet too small");
            break;
        case VFM_ERROR_LIMIT:
            log_error("Execution limit exceeded");
            break;
        // ... handle other errors
    }
}
```

### 3. Use Appropriate Packet Offsets

Common offsets:
- Ethernet header: 0-13
- IP header: 14-33 (minimum)
- TCP header: 34-53 (minimum)

### 4. Validate Packet Structure

Always check packet type before accessing protocol fields:

```assembly
; Validate IPv4 before accessing IP fields
LD16 12         ; EtherType
PUSH 0x0800
JNE skip_ip_checks

; Now safe to access IP fields
LD8 23          ; IP protocol
; ...

skip_ip_checks:
```

### 5. Optimize for Common Case

Place most likely conditions first:

```assembly
; If most traffic is TCP
LD8 23
DUP
PUSH 6          ; TCP
JEQ handle_tcp
PUSH 17         ; UDP
JEQ handle_udp
; ... other protocols
```

## Appendix A: Example Programs

### TCP Port Scanner Detection

```assembly
; Detect TCP SYN to multiple ports from same source
; Uses flow table to track port count per source IP

LD16 12         ; EtherType
PUSH 0x0800     ; IPv4
JNE accept

LD8 23          ; IP Protocol
PUSH 6          ; TCP
JNE accept

LD8 47          ; TCP Flags
PUSH 0x02       ; SYN
AND
PUSH 0x02
JNE accept      ; Not pure SYN

; Create unique key: src_ip | dst_port
LD32 26         ; Source IP
PUSH 16
SHL             ; Shift left 16 bits
LD16 36         ; Destination port
OR              ; Combine

DUP             ; Duplicate key
FLOW_LOAD       ; Check if seen before
PUSH 0
JNE accept      ; Already seen this combination

; Mark as seen
PUSH 1
FLOW_STORE

; Count unique ports per source
LD32 26         ; Source IP
DUP
FLOW_LOAD       ; Get current count
PUSH 1
ADD             ; Increment
DUP             ; Duplicate for comparison
SWAP            ; Get IP back
SWAP            ; Get count on top
FLOW_STORE      ; Store new count

PUSH 20         ; Threshold for port scan
JGT drop        ; More than 20 different ports

accept:
RET 1

drop:
RET 0
```

### DNS Amplification Attack Filter

```assembly
; Drop DNS responses that are too large (amplification attack)

LD16 12         ; EtherType
PUSH 0x0800     ; IPv4
JNE accept

LD8 23          ; IP Protocol
PUSH 17         ; UDP
JNE accept

LD16 34         ; Source port
PUSH 53         ; DNS
JNE accept

; Check packet size
LD16 16         ; IP Total Length
PUSH 512        ; DNS limit
JGT drop        ; Suspiciously large

accept:
RET 1

drop:
RET 0
```

### HTTP Request Logger

```assembly
; Log HTTP GET requests (accept all, but mark GETs)

LD16 12         ; EtherType
PUSH 0x0800     ; IPv4
JNE not_http

LD8 23          ; IP Protocol  
PUSH 6          ; TCP
JNE not_http

LD16 36         ; Destination port
PUSH 80         ; HTTP
JNE not_http

; Check for minimum TCP header + "GET "
LD16 16         ; IP Total Length
PUSH 44         ; Min IP + TCP + 4 bytes
JLT not_http

; Calculate TCP data offset
LD8 46          ; TCP Data offset
PUSH 4
SHR             ; Upper 4 bits
PUSH 4
MUL             ; Convert to bytes

; Check for "GET " (0x47455420)
; Note: This is simplified - real implementation would calculate correct offset
LD32 54         ; Assume standard headers
PUSH 0x47455420
JEQ http_get

not_http:
RET 1           ; Accept but don't log

http_get:
RET 2           ; Special return code for logging
```

### Stateful TCP Connection Tracker

```assembly
; Basic TCP connection state tracking
; Track SYN, SYN-ACK, and established connections

LD16 12         ; EtherType
PUSH 0x0800     ; IPv4
JNE accept

LD8 23          ; IP Protocol
PUSH 6          ; TCP
JNE accept

; Create connection key from 4-tuple
LD32 26         ; Source IP
LD32 30         ; Dest IP
XOR             ; Mix IPs
LD16 34         ; Source Port
LD16 36         ; Dest Port
XOR             ; Mix ports
XOR             ; Final connection ID

DUP             ; Keep connection ID

; Check TCP flags
LD8 47          ; TCP Flags
DUP
PUSH 0x02       ; SYN
AND
PUSH 0x02
JEQ handle_syn

PUSH 0x12       ; SYN-ACK
AND
PUSH 0x12
JEQ handle_syn_ack

PUSH 0x10       ; ACK
AND
PUSH 0x10
JEQ handle_ack

; Other flags - check if connection exists
FLOW_LOAD
PUSH 2          ; Established state
JEQ accept      ; Known connection
RET 0           ; Unknown connection, drop

handle_syn:
POP             ; Remove flags
PUSH 1          ; SYN seen state
FLOW_STORE
RET 1

handle_syn_ack:
POP             ; Remove flags
FLOW_LOAD       ; Check current state
PUSH 1          ; Should be SYN seen
JNE drop
POP             ; Remove old state
PUSH 2          ; Established state
FLOW_STORE
RET 1

handle_ack:
POP             ; Remove flags
FLOW_LOAD       ; Check if established
PUSH 2
JEQ accept
RET 0           ; Not established, drop

accept:
RET 1

drop:
RET 0
```

## Appendix B: Error Codes

### VFM_SUCCESS (0)
Operation completed successfully.

### VFM_ERROR_NO_MEMORY (-1)
Memory allocation failed. Check system resources.

### VFM_ERROR_INVALID_PROGRAM (-2)
Program structure is invalid. Check program size and format.

### VFM_ERROR_INVALID_OPCODE (-3)
Unknown instruction encountered. Verify bytecode integrity.

### VFM_ERROR_STACK_OVERFLOW (-4)
Stack limit exceeded. Reduce stack usage or increase limit.

### VFM_ERROR_STACK_UNDERFLOW (-5)
Attempted to pop from empty stack. Check program logic.

### VFM_ERROR_BOUNDS (-6)
Packet access out of bounds. Validate packet offsets.

### VFM_ERROR_DIVISION_BY_ZERO (-7)
Division by zero attempted. Add zero checks before division.

### VFM_ERROR_LIMIT (-8)
Instruction limit exceeded. Optimize program or increase limit.

### VFM_ERROR_VERIFICATION_FAILED (-9)
Program failed safety verification. Check for:
- Invalid jumps
- Unreachable code
- Stack inconsistencies
- Infinite loops

### Error Handling Example

```c
const char* vfm_error_string(int error) {
    switch (error) {
        case VFM_SUCCESS:
            return "Success";
        case VFM_ERROR_NO_MEMORY:
            return "Out of memory";
        case VFM_ERROR_INVALID_PROGRAM:
            return "Invalid program";
        case VFM_ERROR_INVALID_OPCODE:
            return "Invalid opcode";
        case VFM_ERROR_STACK_OVERFLOW:
            return "Stack overflow";
        case VFM_ERROR_STACK_UNDERFLOW:
            return "Stack underflow";
        case VFM_ERROR_BOUNDS:
            return "Packet bounds exceeded";
        case VFM_ERROR_DIVISION_BY_ZERO:
            return "Division by zero";
        case VFM_ERROR_LIMIT:
            return "Instruction limit exceeded";
        case VFM_ERROR_VERIFICATION_FAILED:
            return "Verification failed";
        default:
            return "Unknown error";
    }
}
```

---

This manual provides comprehensive documentation for developing with VFM. For additional examples and use cases, see the examples/ directory in the VFM distribution.