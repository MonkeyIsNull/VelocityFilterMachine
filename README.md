# Velocity Filter Machine (VFM)

A high-performance packet filtering virtual machine in C, optimized for processing millions of packets per second. VFM features a specialized bytecode interpreter, BPF compilation, zero-copy packet access, and comprehensive safety verification.

## 🚀 Overview

VFM is designed to be the fastest, safest packet filtering VM available. It combines:

- **High Performance**: Optimized interpreter with computed goto dispatch achieving 10M+ packets/second
- **Safety First**: Static program verification prevents crashes and ensures bounded execution
- **Zero-Copy**: Direct packet access without memory copying for maximum throughput
- **Cross-Platform**: Runs on Linux, macOS, and BSD systems
- **BPF Compatible**: Compiles VFM bytecode to native BPF for kernel integration
- **JIT Compilation**: x86-64 and ARM64 JIT compilers for maximum performance

## 🎯 Use Cases

### Network Security
- **DDoS Protection**: Detect and mitigate volumetric attacks
- **Intrusion Detection**: Identify malicious traffic patterns
- **Rate Limiting**: Enforce per-source connection limits

### Traffic Analysis
- **Protocol Analysis**: Parse and classify network protocols
- **Flow Monitoring**: Track connection states and metrics
- **Performance Monitoring**: Measure latency and throughput

### Edge Computing
- **IoT Filtering**: Lightweight packet processing for constrained devices
- **CDN Optimization**: Intelligent traffic routing and caching
- **Load Balancing**: Distribute traffic based on custom rules

## 🛠️ Installation

### Prerequisites
- GCC or Clang compiler
- Make
- Standard C library

### Build from Source
```bash
git clone <repository-url>
cd VelocityFilterMachine
make all
```

This builds:
- `libvfm.a` - Core VFM library
- `vfm-asm` - Assembler (text → bytecode)
- `vfm-dis` - Disassembler (bytecode → text)
- `vfm-test` - Filter testing tool

### Single Header Library
For easy integration, use the single header version:
```c
#define VFM_IMPLEMENTATION
#include "include/vfm.h"
```

## 🏃‍♂️ Quick Start

### 1. Write a Filter
Create `my_filter.vfm`:
```assembly
; Simple TCP port 80 filter
LD16 12         ; Load EtherType
PUSH 0x0800     ; IPv4
JNE reject

LD8 23          ; Load IP protocol
PUSH 6          ; TCP
JNE reject

LD16 36         ; Load destination port
PUSH 80         ; HTTP
JEQ accept

reject:
    RET 0       ; Drop packet
accept:
    RET 1       ; Accept packet
```

### 2. Compile to Bytecode
```bash
./tools/vfm-asm my_filter.vfm -o my_filter.bin
```

### 3. Test the Filter
```bash
./tools/vfm-test my_filter.bin test_packets.pcap
```

### 4. Integrate in C Code
```c
#include "src/vfm.h"

// Load and execute filter
vfm_state_t *vm = vfm_create();
vfm_load_program_file(vm, "my_filter.bin");

// Process packets
int result = vfm_execute(vm, packet_data, packet_len);
if (result == 1) {
    // Accept packet
} else {
    // Drop packet
}

vfm_destroy(vm);
```

## 🧪 Running Tests

### Unit Tests
```bash
make test
```

Runs comprehensive test suite covering:
- VM creation and destruction
- Bounds checking and safety
- Stack operations and arithmetic
- Packet loading and parsing
- Control flow and jumps
- Flow table operations
- Error handling

### Performance Benchmarks
```bash
make benchmark
```

Measures:
- Packets per second throughput
- Nanoseconds per packet latency
- CPU cycles per instruction
- Memory usage patterns

### Individual Test Files
```bash
# Test specific functionality
cd test/
gcc -I../src debug_execute.c ../src/vfm.c ../src/verifier.c -o debug_execute
./debug_execute

# Verify programs
gcc -I../src simple_verify.c ../src/verifier.c -o simple_verify
./simple_verify
```

## 📁 Project Structure

```
VelocityFilterMachine/
├── src/                    # Core implementation
│   ├── vfm.c              # Main VM interpreter
│   ├── vfm.h              # Public API
│   ├── opcodes.h          # Instruction definitions
│   ├── verifier.c         # Safety validation
│   ├── compiler.c         # BPF compilation
│   ├── jit_x86_64.c       # x86-64 JIT
│   └── jit_arm64.c        # ARM64 JIT
├── tools/                  # Command-line tools
│   ├── vfm-asm.c          # Assembler
│   ├── vfm-dis.c          # Disassembler
│   └── vfm-test.c         # Testing tool
├── examples/               # Example filters
│   ├── tcp_filter.vfm     # TCP filtering
│   ├── ddos_detect.vfm    # DDoS detection
│   ├── rate_limit.vfm     # Rate limiting
│   └── *.bin              # Compiled bytecode
├── test/                   # Test suite
│   ├── test_vfm.c         # Unit tests
│   ├── test_packets.pkt   # Test data
│   └── debug_*.c          # Debug tools
├── bench/                  # Performance benchmarks
│   └── bench.c
├── include/                # Single header library
│   └── vfm.h
└── Makefile               # Build configuration
```

## 🔧 Advanced Usage

### Assembly Language Reference
VFM uses a stack-based instruction set:

**Packet Access:**
- `LD8 offset` - Load byte from packet
- `LD16 offset` - Load 16-bit value (network order)
- `LD32 offset` - Load 32-bit value (network order)
- `LD64 offset` - Load 64-bit value (network order)

**Stack Operations:**
- `PUSH value` - Push 64-bit immediate
- `POP` - Pop top value
- `DUP` - Duplicate top value
- `SWAP` - Swap top two values

**Arithmetic:**
- `ADD`, `SUB`, `MUL`, `DIV`, `MOD`
- `AND`, `OR`, `XOR`, `NOT`
- `SHL`, `SHR` - Bit shifting

**Control Flow:**
- `JMP offset` - Unconditional jump
- `JEQ offset` - Jump if equal
- `JNE offset` - Jump if not equal
- `JGT offset` - Jump if greater
- `JLT offset` - Jump if less
- `RET` - Return with top stack value

**Special Operations:**
- `HASH5` - Hash 5-tuple for flow tracking
- `FLOW_LOAD` - Load from flow table
- `FLOW_STORE` - Store to flow table

### BPF Compilation
Convert VFM bytecode to BPF:
```bash
./tools/vfm-compile filter.bin --target=ebpf -o filter.bpf
```

### JIT Compilation
Enable JIT for maximum performance:
```c
vfm_state_t *vm = vfm_create();
vfm_enable_jit(vm);  // Compile to native code
```

## 📊 Performance

VFM achieves exceptional performance through:

- **Computed Goto**: Eliminates switch statement overhead
- **Cache Optimization**: Data structures aligned for modern CPUs
- **Bounds Checking**: Optimized memory access validation
- **JIT Compilation**: Native code generation for hot paths

Benchmark results on Apple M2:
- **Simple filters**: 25M+ packets/second
- **Complex filters**: 10M+ packets/second
- **Memory usage**: <1MB per VM instance

## 🔒 Security

VFM prioritizes safety with:

- **Static Verification**: Programs validated before execution
- **Bounded Execution**: Instruction count limits prevent infinite loops
- **Memory Safety**: All packet access is bounds-checked
- **Stack Protection**: Stack overflow/underflow detection
- **No Unsafe Operations**: No raw memory access or system calls

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite: `make test`
6. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🎯 Performance Goals

- **Throughput**: 10M+ packets/second for simple filters
- **Latency**: <50ns per packet overhead
- **Memory**: <1MB per VM instance
- **Safety**: Zero crashes on malformed bytecode
- **Compatibility**: Runs on Linux, macOS, BSD

