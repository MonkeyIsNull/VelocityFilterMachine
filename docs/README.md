# VFM Documentation

This directory contains comprehensive documentation for the Velocity Filter Machine (VFM).

## Files

- `programming_manual.md` - Complete programming guide with examples
- `simple_filter.vfm` - Basic IPv4 filter example
- `tcp_port_filter.vfm` - TCP port 80/443 filter example
- `dns_amplification_filter.vfm` - DNS amplification attack prevention
- `arithmetic_example.vfm` - Basic arithmetic operations
- `test_filter.c` - C example showing API usage
- `unit_test_style.c` - Working C test based on unit test patterns

## Compiled Examples

All `.vfm` files can be compiled using the assembler:

```bash
../tools/vfm-asm example.vfm -o example.bin
```

And disassembled for verification:

```bash
../tools/vfm-dis example.bin
```

## Testing Examples

The C test programs demonstrate proper API usage. The unit_test_style.c shows the correct way to integrate with VFM:

```bash
gcc -I../src unit_test_style.c ../libvfm.a -o unit_test_style
./unit_test_style
```

This example demonstrates:
- Proper VM initialization
- Bytecode loading using raw arrays (recommended approach)
- Correct packet structure creation
- Error handling and cleanup

## Key Points for C Integration

1. Always use proper packet structures with valid headers
2. Provide correct packet lengths to vfm_execute
3. Check return codes from all VFM functions
4. Use vfm_verify for untrusted programs
5. Initialize flow tables if using stateful filtering

## Performance Testing

Use the built-in tools for performance analysis:

```bash
# Test against packet captures
../tools/vfm-test filter.bin packets.pcap

# Generate performance benchmarks
cd ../bench && make && ./bench
```