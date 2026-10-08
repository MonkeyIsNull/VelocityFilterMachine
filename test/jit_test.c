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

// The execute-vs-oracle harness runs on whichever single-core JIT the host
// architecture provides. #11 wired this up for ARM64; this adds the x86-64 twin
// so the single-core x86 emitters are finally EXECUTED and asserted equal to the
// interpreter oracle (the blind spot that hid the LD8 high-bits bug). Each arch
// exposes a different compiler symbol and page size; JIT_COMPILE/JIT_MUNMAP_SIZE
// abstract that. On a host whose JIT is unavailable or declines a program,
// check_exec reports a clean DECLINE/skip rather than failing, so the harness is
// safe to run everywhere (e.g. every load/arith program is declined on ARM64,
// whose single-core set is PUSH/ADD/RET).
#if defined(__aarch64__)
extern void* vfm_jit_compile_arm64(const uint8_t *program, uint32_t len);
extern bool  vfm_jit_available_arm64(void);
#define JIT_COMPILE(p, l)     vfm_jit_compile_arm64((p), (l))
#define JIT_MUNMAP_SIZE(l)    ((size_t)4096)
#elif defined(__x86_64__)
extern void* vfm_jit_compile_x86_64(const uint8_t *program, uint32_t len);
#define JIT_COMPILE(p, l)     vfm_jit_compile_x86_64((p), (l))
// vfm_jit_compile_x86_64 maps len*32 bytes; munmap the same span.
#define JIT_MUNMAP_SIZE(l)    ((size_t)(l) * 32)
#endif

#if defined(__aarch64__) || defined(__x86_64__)
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
// interpreter oracle. This is the gate that would have caught the shipped SEGV
// (ARM64) and the LD8 high-bits divergence (x86-64).
static void check_exec(const char *name, const uint8_t *prog, uint32_t plen,
                       const uint8_t *pkt, uint16_t pktlen) {
    void *code = JIT_COMPILE(prog, plen);
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
    // dropped the high bits, even the low-32 compare would diverge. The LD8/LD16
    // programs catch the high-bits-garbage bug: any stale bits above the loaded
    // width make jit_i diverge from the interpreter's zero-extended value.)
    int jit_i = (int)jit_raw;
    int jit_map = (jit_i > 0) ? 1 : 0;
    int ora_map = (oracle > 0) ? 1 : 0;
    bool ok = (jit_map == ora_map) && (jit_i == oracle);
    printf("   [%s] jit=%d oracle=%d -> %s\n", name, jit_i, oracle, ok ? "OK" : "MISMATCH");
    if (!ok) failures++;
    munmap(code, JIT_MUNMAP_SIZE(plen));
}

// Shared per-opcode oracle suite. Runs on both arches: on x86-64 every program
// below compiles and executes; on ARM64 the load/arith programs are DECLINED
// (its trusted set is PUSH/ADD/RET) and check_exec reports a skip, so ARM64
// stays green while x86-64 gets full coverage.
static void run_oracle_suite(void) {
    uint8_t pkt[64];
    // A plausible IPv4/TCP-ish packet: proto byte (offset 9) = 6 (TCP).
    for (int i = 0; i < 64; i++) pkt[i] = (uint8_t)(i + 1);
    pkt[9] = 6;    // proto == 6
    pkt[12] = 0xC0; pkt[13] = 0xA8; pkt[14] = 0x00; pkt[15] = 0x01; // 192.168.0.1

    int k;

    // PUSH 42; RET
    uint8_t p42[10]; p42[0]=VFM_PUSH; put64(p42+1,42); p42[9]=VFM_RET;
    check_exec("PUSH42;RET", p42, sizeof(p42), pkt, sizeof(pkt));

    // > 0xFFFF immediates (catch any imm truncation).
    uint8_t big[10]; big[0]=VFM_PUSH; put64(big+1, 0x1122334455ULL); big[9]=VFM_RET;
    check_exec("PUSH_big;RET", big, sizeof(big), pkt, sizeof(pkt));
    uint8_t big2[10]; big2[0]=VFM_PUSH; put64(big2+1, 0xDEADBEEFCAFEULL); big2[9]=VFM_RET;
    check_exec("PUSH_big2;RET", big2, sizeof(big2), pkt, sizeof(pkt));

    // PUSH 10; PUSH 32; ADD; RET -> 42 (multi-slot stack).
    uint8_t addp[22]; k=0;
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

    // Deep stack: PUSH 1..6; ADD x5; RET -> 21. Reaches operand-stack depth 6,
    // allocating R8-R13 and thus exercising the callee-saved R12/R13 that the
    // prologue/epilogue must preserve across the call (a missing save corrupts
    // the C harness's own registers after the call).
    uint8_t deep[80]; k=0;
    for (uint64_t v = 1; v <= 6; v++) { deep[k++]=VFM_PUSH; put64(deep+k, v); k+=8; }
    for (int i = 0; i < 5; i++) deep[k++]=VFM_ADD;
    deep[k++]=VFM_RET;
    check_exec("PUSH x6;ADD x5;RET (depth 6)", deep, (uint32_t)k, pkt, sizeof(pkt));

    // SUB: PUSH 100; PUSH 58; SUB; RET -> 42.
    uint8_t subp[22]; k=0;
    subp[k++]=VFM_PUSH; put64(subp+k,100); k+=8;
    subp[k++]=VFM_PUSH; put64(subp+k,58); k+=8;
    subp[k++]=VFM_SUB; subp[k++]=VFM_RET;
    check_exec("PUSH;PUSH;SUB;RET", subp, (uint32_t)k, pkt, sizeof(pkt));

    // MUL: PUSH 6; PUSH 7; MUL; RET -> 42.
    uint8_t mulp[22]; k=0;
    mulp[k++]=VFM_PUSH; put64(mulp+k,6); k+=8;
    mulp[k++]=VFM_PUSH; put64(mulp+k,7); k+=8;
    mulp[k++]=VFM_MUL; mulp[k++]=VFM_RET;
    check_exec("PUSH;PUSH;MUL;RET", mulp, (uint32_t)k, pkt, sizeof(pkt));

    // AND/OR/XOR.
    uint8_t andp[22]; k=0;
    andp[k++]=VFM_PUSH; put64(andp+k,0xF0); k+=8;
    andp[k++]=VFM_PUSH; put64(andp+k,0x3C); k+=8;
    andp[k++]=VFM_AND; andp[k++]=VFM_RET;
    check_exec("AND", andp, (uint32_t)k, pkt, sizeof(pkt));
    uint8_t orp[22]; k=0;
    orp[k++]=VFM_PUSH; put64(orp+k,0xF0); k+=8;
    orp[k++]=VFM_PUSH; put64(orp+k,0x0C); k+=8;
    orp[k++]=VFM_OR; orp[k++]=VFM_RET;
    check_exec("OR", orp, (uint32_t)k, pkt, sizeof(pkt));
    uint8_t xorp[22]; k=0;
    xorp[k++]=VFM_PUSH; put64(xorp+k,0xFF); k+=8;
    xorp[k++]=VFM_PUSH; put64(xorp+k,0x0F); k+=8;
    xorp[k++]=VFM_XOR; xorp[k++]=VFM_RET;
    check_exec("XOR", xorp, (uint32_t)k, pkt, sizeof(pkt));

    // SHL/SHR: PUSH 1; PUSH 10; SHL; RET -> 1024 ; and PUSH 1024; PUSH 3; SHR -> 128
    uint8_t shlp[22]; k=0;
    shlp[k++]=VFM_PUSH; put64(shlp+k,1); k+=8;
    shlp[k++]=VFM_PUSH; put64(shlp+k,10); k+=8;
    shlp[k++]=VFM_SHL; shlp[k++]=VFM_RET;
    check_exec("SHL", shlp, (uint32_t)k, pkt, sizeof(pkt));
    uint8_t shrp[22]; k=0;
    shrp[k++]=VFM_PUSH; put64(shrp+k,1024); k+=8;
    shrp[k++]=VFM_PUSH; put64(shrp+k,3); k+=8;
    shrp[k++]=VFM_SHR; shrp[k++]=VFM_RET;
    check_exec("SHR", shrp, (uint32_t)k, pkt, sizeof(pkt));

    // NOT/NEG then mask to a small value so (int) comparison is meaningful.
    // PUSH 0; NOT; PUSH 0xFF; AND; RET -> 0xFF.
    uint8_t notp[32]; k=0;
    notp[k++]=VFM_PUSH; put64(notp+k,0); k+=8;
    notp[k++]=VFM_NOT;
    notp[k++]=VFM_PUSH; put64(notp+k,0xFF); k+=8;
    notp[k++]=VFM_AND; notp[k++]=VFM_RET;
    check_exec("NOT;AND", notp, (uint32_t)k, pkt, sizeof(pkt));

    // DUP: PUSH 21; DUP; ADD; RET -> 42.
    uint8_t dupp[12]; k=0;
    dupp[k++]=VFM_PUSH; put64(dupp+k,21); k+=8;
    dupp[k++]=VFM_DUP; dupp[k++]=VFM_ADD; dupp[k++]=VFM_RET;
    check_exec("DUP;ADD", dupp, (uint32_t)k, pkt, sizeof(pkt));

    // SWAP: PUSH 50; PUSH 8; SWAP; SUB; RET -> 8-50 = -42 (wraps; compared as int).
    uint8_t swapp[24]; k=0;
    swapp[k++]=VFM_PUSH; put64(swapp+k,50); k+=8;
    swapp[k++]=VFM_PUSH; put64(swapp+k,8); k+=8;
    swapp[k++]=VFM_SWAP; swapp[k++]=VFM_SUB; swapp[k++]=VFM_RET;
    check_exec("SWAP;SUB", swapp, (uint32_t)k, pkt, sizeof(pkt));

    // POP: PUSH 7; PUSH 99; POP; RET -> 7.
    uint8_t popp[21]; k=0;
    popp[k++]=VFM_PUSH; put64(popp+k,7); k+=8;
    popp[k++]=VFM_PUSH; put64(popp+k,99); k+=8;
    popp[k++]=VFM_POP; popp[k++]=VFM_RET;
    check_exec("POP", popp, (uint32_t)k, pkt, sizeof(pkt));

    // LD8 at the proto offset -> 6. Exercises MOVZX zero-extension directly.
    uint8_t ld8[] = { VFM_LD8, 9,0, VFM_RET };
    check_exec("LD8[9]->proto", ld8, sizeof(ld8), pkt, sizeof(pkt));

    // The headline bug: LD8 then a wide operation that EXPOSES high bits.
    // Dirty a register first (PUSH big; POP leaves the value in the reg the
    // next LD8 reuses), then LD8 proto; PUSH 6; XOR; RET. If LD8 zero-extends
    // correctly the result is 6^6 = 0 (DROP); if it leaves stale high bits the
    // XOR is non-zero (ACCEPT) and diverges from the interpreter's 0.
    uint8_t ld8x[40]; k=0;
    ld8x[k++]=VFM_PUSH; put64(ld8x+k,0xFFFFFFFFFFFFFF00ULL); k+=8;
    ld8x[k++]=VFM_POP;
    ld8x[k++]=VFM_LD8; ld8x[k++]=9; ld8x[k++]=0;
    ld8x[k++]=VFM_PUSH; put64(ld8x+k,6); k+=8;
    ld8x[k++]=VFM_XOR; ld8x[k++]=VFM_RET;
    check_exec("proto==6 LD8+XOR", ld8x, (uint32_t)k, pkt, sizeof(pkt));

    // LD16 at offset 12 -> ntohs(bytes 0xC0,0xA8) = 0xC0A8 = 49320.
    uint8_t ld16[] = { VFM_LD16, 12,0, VFM_RET };
    check_exec("LD16[12]", ld16, sizeof(ld16), pkt, sizeof(pkt));

    // LD32 at offset 12 -> ntohl(C0 A8 00 01) = 0xC0A80001 (as int = negative).
    uint8_t ld32[] = { VFM_LD32, 12,0, VFM_RET };
    check_exec("LD32[12]", ld32, sizeof(ld32), pkt, sizeof(pkt));

    // LD8 at a NONZERO offset whose value is known: pkt[20] = 21 -> compare.
    uint8_t ld8b[] = { VFM_LD8, 20,0, VFM_RET };
    check_exec("LD8[20]", ld8b, sizeof(ld8b), pkt, sizeof(pkt));

    // Out-of-bounds load: offset 100 in a 64-byte packet. The interpreter
    // returns VFM_ERROR_BOUNDS (-1); the JIT's emitted bounds check must match.
    uint8_t oob[] = { VFM_LD8, 100,0, VFM_RET };
    check_exec("LD8_OOB[100]", oob, sizeof(oob), pkt, sizeof(pkt));

    // Control flow must DECLINE on both arches (x86 branch fixups unimplemented):
    // LD8 9; PUSH 6; JEQ +1; RET. check_exec reports a clean decline/skip.
    uint8_t br[16]; k=0;
    br[k++]=VFM_LD8; br[k++]=9; br[k++]=0;
    br[k++]=VFM_PUSH; put64(br+k,6); k+=8;
    br[k++]=VFM_JEQ; br[k++]=1; br[k++]=0;
    br[k++]=VFM_RET;
    check_exec("proto==6 branch (expect DECLINE)", br, (uint32_t)k, pkt, sizeof(pkt));
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
    printf("VFM JIT execute-vs-oracle test\n");
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
    void *gate_code = JIT_COMPILE(gate, sizeof(gate));
    if (!gate_code) {
        printf("   FAIL: JIT available but a known-compilable program yielded NULL\n");
        return 1;
    }
    printf("   PASS: compiled to %p\n", gate_code);
    munmap(gate_code, JIT_MUNMAP_SIZE(sizeof(gate)));

    printf("\n3. Execute compiled code and compare to the interpreter oracle...\n");
    run_oracle_suite();

    // A program with an opcode outside the ARM64 trusted set (LD16) must
    // DECLINE, not SEGV. (On x86-64 LD16 is a supported, oracle-validated
    // emitter, so this specific NULL assertion is ARM64-only.)
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
#elif defined(__x86_64__)
    printf("   x86-64 single-core JIT: always available (no entitlement needed)\n");

    // JIT-active hard gate: PUSH 42; RET MUST compile to a non-NULL page.
    printf("\n2. JIT-active gate (PUSH 42; RET must compile)...\n");
    uint8_t gate[] = { VFM_PUSH, 42,0,0,0,0,0,0,0, VFM_RET };
    void *gate_code = JIT_COMPILE(gate, sizeof(gate));
    if (!gate_code) {
        printf("   FAIL: x86-64 JIT yielded NULL for a known-compilable program\n");
        return 1;
    }
    printf("   PASS: compiled to %p\n", gate_code);
    munmap(gate_code, JIT_MUNMAP_SIZE(sizeof(gate)));

    printf("\n3. Execute compiled x86-64 code and compare to the interpreter oracle...\n");
    run_oracle_suite();

    check_cache_teardown();

    if (failures) {
        printf("\nFAILED: %d JIT execution mismatch(es)\n", failures);
        return 1;
    }
    printf("\nAll JIT execution tests passed (JIT == interpreter oracle).\n");
    return 0;
#else
    printf("   Not running on x86-64 or ARM64 - JIT execution test skipped\n");
    check_cache_teardown();
    if (failures) {
        printf("\nFAILED: %d JIT test failure(s)\n", failures);
        return 1;
    }
    return 0;
#endif
}
