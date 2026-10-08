#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "vfm.h"

// JIT calling convention (see include/vfm.h): the compiled function takes the
// packet, its length, and explicit pointers to caller-owned operand stacks.
typedef uint64_t (*vfm_jit_fn_t)(const uint8_t *packet, uint16_t packet_len,
                                 uint64_t *stack64, vfm_u128_t *stack128);

static int failures = 0;

static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

#ifdef __aarch64__
extern void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len);
extern bool  vfm_jit_available_arm64(void);

// Run (program, packet) through an interpreter-only VM -- the oracle.
static int interp_result(const uint8_t *prog, uint32_t plen,
                         const uint8_t *pkt, uint16_t pktlen) {
    vfm_state_t *vm = vfm_create();
    vm->cold.jit_enabled = false;  // force the interpreter
    int rc = vfm_load_program(vm, prog, plen);
    if (rc != VFM_SUCCESS) { vfm_destroy(vm); return -999; }
    if (vm->cold.jit_code != NULL) { vfm_destroy(vm); return -998; } // must be interpreter
    int r = vfm_execute(vm, pkt, pktlen);
    vfm_destroy(vm);
    return r;
}

// Compile, execute via the real JIT ABI, and compare the RAW result to the
// interpreter oracle. This is the gate that would have caught the shipped SEGV.
static void check_exec(const char *name, const uint8_t *prog, uint32_t plen,
                       const uint8_t *pkt, uint16_t pktlen) {
    void *code = vfm_jit_compile_arm64(prog, plen);
    if (!code) {
        printf("   [%s] JIT DECLINED (interpreter fallback) -- skipping exec check\n", name);
        return;
    }
    uint64_t stack64[VFM_MAX_STACK];
    vfm_u128_t stack128[VFM_MAX_STACK];
    memset(stack64, 0, sizeof(stack64));
    memset(stack128, 0, sizeof(stack128));

    vfm_jit_fn_t fn = (vfm_jit_fn_t)code;
    uint64_t jit_raw = fn(pkt, pktlen, stack64, stack128);
    int oracle = interp_result(prog, plen, pkt, pktlen);

    // The engine's observable result is int: vfm_execute returns (int)result and
    // op_ret truncates the same way, so compare the JIT's top-of-stack as an int
    // against the interpreter oracle, plus the (accept/drop) mapping. (The
    // >0xFFFF immediates still catch the old 16-bit MOVZ truncation: if PUSH
    // dropped the high bits, even the low-32 compare would diverge.)
    int jit_i = (int)jit_raw;
    int jit_map = (jit_i > 0) ? 1 : 0;
    int ora_map = (oracle > 0) ? 1 : 0;
    bool ok = (jit_map == ora_map) && (jit_i == oracle);
    printf("   [%s] jit=%d oracle=%d -> %s\n", name, jit_i, oracle, ok ? "OK" : "MISMATCH");
    if (!ok) failures++;
    munmap(code, 4096);
}
#endif

// Regression for the single-core JIT cache teardown use-after-free.
// The JIT cache is opt-in (an app must call vfm_jit_cache_init); once enabled,
// two VMs that load the SAME program get a cache HIT and share one RX page the
// cache owns. The pre-fix teardown released the ref AND then munmap'd that
// shared page, leaving the bucket with a dangling pointer -- a later VM loading
// the same program executed freed memory and SEGV'd. This asserts the shared
// page survives one sharer's destruction. Portable (public API only); on any
// build where the JIT is unavailable or declines, it reports SKIP, not failure.
static void check_cache_teardown(void) {
    printf("\n4. Single-core JIT cache teardown (UAF regression)...\n");
    if (vfm_jit_cache_init(NULL) != VFM_SUCCESS) {
        printf("   SKIP: JIT cache unavailable\n");
        return;
    }

    uint8_t prog[10]; prog[0] = VFM_PUSH; put64(prog + 1, 7); prog[9] = VFM_RET;
    uint8_t pkt[64]; memset(pkt, 0xAB, sizeof(pkt));

    // Interpreter-only oracle.
    vfm_state_t *ovm = vfm_create();
    ovm->cold.jit_enabled = false;
    vfm_load_program(ovm, prog, sizeof(prog));
    int oracle = vfm_execute(ovm, pkt, sizeof(pkt));
    vfm_destroy(ovm);

    // VM #1: compile + store in cache, execute, destroy (the teardown under test).
    vfm_state_t *v1 = vfm_create();
    vfm_load_program(v1, prog, sizeof(prog));
    void *p1 = v1->cold.jit_code;
    int r1 = vfm_execute(v1, pkt, sizeof(pkt));
    vfm_destroy(v1);

    if (p1 == NULL) {
        printf("   SKIP: JIT inactive on this build (cache page never populated)\n");
        return;
    }

    // VM #2: same program -> cache HIT -> reuses the page VM #1's teardown touched.
    vfm_state_t *v2 = vfm_create();
    vfm_load_program(v2, prog, sizeof(prog));
    void *p2 = v2->cold.jit_code;
    int r2 = vfm_execute(v2, pkt, sizeof(pkt));   // pre-fix: executes a freed page
    vfm_destroy(v2);

    // VM #3: once more, to catch a bucket left dangling.
    vfm_state_t *v3 = vfm_create();
    vfm_load_program(v3, prog, sizeof(prog));
    int r3 = vfm_execute(v3, pkt, sizeof(pkt));
    vfm_destroy(v3);

    bool shared = (p1 == p2);
    bool ok = shared && r1 == oracle && r2 == oracle && r3 == oracle;
    printf("   p1=%p p2=%p shared=%s r1=%d r2=%d r3=%d oracle=%d -> %s\n",
           p1, p2, shared ? "YES" : "no", r1, r2, r3, oracle, ok ? "OK" : "FAIL");
    if (!ok) failures++;
}

int main(void) {
    printf("VFM JIT Test on Apple Silicon\n");
    printf("==============================\n\n");

    printf("1. Testing JIT availability...\n");

#ifdef __aarch64__
    bool jit_available = vfm_jit_available_arm64();
    printf("   ARM64 JIT available: %s\n", jit_available ? "YES" : "NO");
    if (!jit_available) {
        printf("   ERROR: JIT not available. The test binary must be codesigned\n");
        printf("   with entitlements.plist (com.apple.security.cs.allow-jit).\n");
        return 1;
    }

    // JIT-active hard gate: a known-compilable program (PUSH 42; RET) MUST yield
    // a non-NULL page when the JIT is available. If it does not, the JIT path is
    // silently broken -- fail loudly rather than pass on the interpreter.
    printf("\n2. JIT-active gate (PUSH 42; RET must compile)...\n");
    uint8_t gate[] = { VFM_PUSH, 42,0,0,0,0,0,0,0, VFM_RET };
    void *gate_code = vfm_jit_compile_arm64(gate, sizeof(gate));
    if (!gate_code) {
        printf("   FAIL: JIT available but a known-compilable program yielded NULL\n");
        return 1;
    }
    printf("   PASS: compiled to %p\n", gate_code);
    munmap(gate_code, 4096);

    printf("\n3. Execute compiled code and compare to the interpreter oracle...\n");
    uint8_t pkt[64];
    memset(pkt, 0, sizeof(pkt));

    // PUSH 42; RET
    check_exec("PUSH42;RET", gate, sizeof(gate), pkt, sizeof(pkt));

    // PUSH 0x1122334455; RET  -- immediate well above 0xFFFF catches the old
    // 16-bit MOVZ truncation bug.
    uint8_t big[10]; big[0]=VFM_PUSH; put64(big+1, 0x1122334455ULL); big[9]=VFM_RET;
    check_exec("PUSH_big;RET", big, sizeof(big), pkt, sizeof(pkt));

    // PUSH 0xDEADBEEFCAFE; RET -- another > 32-bit immediate.
    uint8_t big2[10]; big2[0]=VFM_PUSH; put64(big2+1, 0xDEADBEEFCAFEULL); big2[9]=VFM_RET;
    check_exec("PUSH_big2;RET", big2, sizeof(big2), pkt, sizeof(pkt));

    // PUSH 10; PUSH 32; ADD; RET -> 42 (multi-value stack exercises index-based
    // addressing, catching the old fixed-offset stack bug).
    uint8_t addp[22]; int k=0;
    addp[k++]=VFM_PUSH; put64(addp+k,10); k+=8;
    addp[k++]=VFM_PUSH; put64(addp+k,32); k+=8;
    addp[k++]=VFM_ADD; addp[k++]=VFM_RET;
    check_exec("PUSH;PUSH;ADD;RET", addp, (uint32_t)k, pkt, sizeof(pkt));

    // PUSH 1; PUSH 2; PUSH 3; ADD; ADD; RET -> 6 (deeper stack).
    uint8_t add3[40]; k=0;
    add3[k++]=VFM_PUSH; put64(add3+k,1); k+=8;
    add3[k++]=VFM_PUSH; put64(add3+k,2); k+=8;
    add3[k++]=VFM_PUSH; put64(add3+k,3); k+=8;
    add3[k++]=VFM_ADD; add3[k++]=VFM_ADD; add3[k++]=VFM_RET;
    check_exec("PUSH x3;ADD x2;RET", add3, (uint32_t)k, pkt, sizeof(pkt));

    // A program with an unimplemented opcode (LD16) must DECLINE, not SEGV.
    uint8_t decl[] = { VFM_LD16, 36,0, VFM_RET };
    void *d = vfm_jit_compile_arm64(decl, sizeof(decl));
    printf("   [decline LD16] %s\n", d==NULL ? "OK (NULL)" : "FAIL (non-NULL)");
    if (d != NULL) { failures++; munmap(d, 4096); }

    check_cache_teardown();

    if (failures) {
        printf("\nFAILED: %d JIT execution mismatch(es)\n", failures);
        return 1;
    }
    printf("\nAll JIT execution tests passed (JIT == interpreter oracle).\n");
    return 0;
#else
    printf("   Not running on ARM64 - JIT execution test skipped\n");
    check_cache_teardown();
    if (failures) {
        printf("\nFAILED: %d JIT test failure(s)\n", failures);
        return 1;
    }
    return 0;
#endif
}
