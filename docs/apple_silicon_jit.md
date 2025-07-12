# Apple Silicon JIT Requirements

## Overview
Running JIT code on Apple Silicon (M1, M2, M3+ chips) requires special handling due to Apple's security hardening. This document explains the requirements and implementation details.

## Key Requirements

### 1. MAP_JIT Flag
- Must use `MAP_JIT` flag when calling `mmap()` for JIT memory allocation
- Cannot use `PROT_EXEC` in initial `mmap()` call on Apple Silicon

### 2. W^X (Write XOR Execute) Enforcement
Apple Silicon enforces that memory pages cannot be both writable and executable simultaneously:

1. **Write Phase**: Allocate memory with `PROT_READ | PROT_WRITE` and `MAP_JIT`
2. **Generate Code**: Write JIT instructions to memory
3. **Execute Phase**: 
   - Call `sys_icache_invalidate()` to flush instruction cache
   - Call `pthread_jit_write_protect_np(1)` to enable write protection
   - Change memory protection to `PROT_READ | PROT_EXEC` using `mprotect()`

### 3. Entitlements
The application must have the `com.apple.security.cs.allow-jit` entitlement:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.cs.allow-jit</key>
    <true/>
</dict>
</plist>
```

### 4. Code Signing
For distribution, the application must be properly code-signed with the JIT entitlement.

## Implementation Details

### Memory Allocation
```c
#ifdef __APPLE__
// Apple Silicon - use MAP_JIT
uint8_t *code = mmap(NULL, size, PROT_READ | PROT_WRITE, 
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
// Other platforms - traditional RWX
uint8_t *code = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
```

### Finalizing JIT Code
```c
#ifdef __APPLE__
// Flush instruction cache
sys_icache_invalidate(code, code_size);

// Enable write protection
pthread_jit_write_protect_np(1);

// Make executable
mprotect(code, code_size, PROT_READ | PROT_EXEC);
#else
// Other platforms - just flush cache
__builtin___clear_cache((char*)code, (char*)code + code_size);
#endif
```

### Runtime Detection
```c
bool vfm_jit_available_arm64(void) {
#ifdef __APPLE__
    // Test if JIT is available by trying to allocate JIT memory
    void *test_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE, 
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
    if (test_mem == MAP_FAILED) {
        return false;  // JIT not available
    }
    munmap(test_mem, 4096);
    return true;
#else
    return true;
#endif
}
```

## Building with JIT Support

### Development/Testing
For development, you can disable SIP (System Integrity Protection) to bypass some restrictions:
```bash
# Disable SIP (requires reboot to recovery mode)
csrutil disable

# Re-enable SIP when done
csrutil enable
```

### Production Build
1. Add entitlements file (`entitlements.plist`)
2. Sign the binary:
```bash
codesign --entitlements entitlements.plist -s "Developer ID Application" your_app
```

## Fallback Strategy
If JIT is not available:
1. Fall back to interpreter mode
2. Use ahead-of-time compilation to BPF/eBPF
3. Use function pointer tables for dispatch

## Testing
```bash
# Check if JIT is working
./vfm-test --jit-test

# Run with JIT disabled to test fallback
./vfm-test --no-jit
```

## Common Issues

1. **"Operation not permitted" when calling mmap()**: Missing JIT entitlement
2. **Bus error/segmentation fault**: Trying to execute non-executable memory
3. **Cache coherency issues**: Forgot to flush instruction cache

## References
- [Apple Developer Documentation - Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime)
- [Apple Silicon JIT Best Practices](https://developer.apple.com/forums/thread/678609)
- [pthread_jit_write_protect_np Documentation](https://developer.apple.com/documentation/kernel/1643512-pthread_jit_write_protect_np)
