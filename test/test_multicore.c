// test_multicore.c -- end-to-end tests for the multicore adaptive-JIT subsystem.
//
// Core principle: the single-core interpreter is the ORACLE. Multicore batch
// results must equal the interpreter over the same (program, packet) pairs,
// using the (result > 0) ? 1 : 0 accept/drop mapping on both sides. Covers:
//   - JIT-active hard gate (no silent interpreter-only pass)
//   - correctness vs oracle across JIT'd AND declined (port/proto/IPv6) filters
//   - num_cores in {1,2,8}, batch sizes that do not divide evenly and that are
//     smaller than the core count (remainder + empty-range workers)
//   - recompilation triggering (threshold lowered) -> opt_level ADAPTIVE, the
//     shared page pointer changes, every core re-points, results still match
//   - declined recompile leaves the previous state valid (UAF regression)
//   - hundreds of back-to-back batches on 8 cores under an INDEPENDENT watchdog
//     that _exit()s on timeout (so a deadlock fails the run, not hangs CI)
//   - two concurrent mc_vm instances (per-instance counters, not a shared static)
//   - program-lifetime: the caller's program buffer is freed between batches
//     (works only because load_program copies the program)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include "vfm.h"

static int g_failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("   FAIL: %s\n", (msg)); g_failures++; } \
} while (0)

// ---------------------------------------------------------------------------
// Independent watchdog: if the whole suite has not finished within the budget,
// print and _exit(nonzero). Runs on its own thread so it fires even if the main
// thread is wedged inside execute_batch.
// ---------------------------------------------------------------------------
static volatile int g_done = 0;
static void *watchdog(void *arg) {
    int seconds = *(int*)arg;
    for (int i = 0; i < seconds * 10; i++) {
        usleep(100000);  // 100ms
        if (g_done) return NULL;
    }
    fprintf(stderr, "\nWATCHDOG TIMEOUT: multicore suite did not finish -- likely deadlock. FAIL.\n");
    _exit(3);
}

static void put64(uint8_t *p, uint64_t v) { memcpy(p, &v, 8); }

// Create a multicore VM. Under TSan (VFM_TSAN_NO_JIT) the JIT is disabled so the
// concurrency model (barrier, completed_count, publication ordering, per-core
// stats) is exercised WITHOUT RX MAP_JIT pages, which TSan cannot instrument and
// whose thread-local W^X toggle it cannot reason about. JIT correctness and the
// recompile lifecycle are covered separately under ASan with the JIT enabled.
static vfm_multicore_state_t *mc_new(uint32_t n) {
    vfm_multicore_state_t *mc = vfm_multicore_create(n);
#ifdef VFM_TSAN_NO_JIT
    if (mc) mc->shared->jit_enabled = false;
#endif
    return mc;
}

// ---------------------------------------------------------------------------
// Program corpus. `jit_ok` marks programs the ARM64 JIT is expected to compile
// (PUSH/ADD/RET); the rest must DECLINE and run on the per-core interpreter.
// ---------------------------------------------------------------------------
typedef struct { const char *name; uint8_t code[64]; uint32_t len; bool jit_ok; } prog_t;

static prog_t make_accept_all(void) {
    prog_t p = { .name = "accept_all", .jit_ok = true };
    uint32_t k = 0;
    p.code[k++] = VFM_PUSH; put64(p.code+k, 1); k += 8;
    p.code[k++] = VFM_RET;
    p.len = k; return p;
}
static prog_t make_drop_all(void) {
    prog_t p = { .name = "drop_all", .jit_ok = true };
    uint32_t k = 0;
    p.code[k++] = VFM_PUSH; put64(p.code+k, 0); k += 8;
    p.code[k++] = VFM_RET;
    p.len = k; return p;
}
static prog_t make_add(void) {
    prog_t p = { .name = "add_nonzero", .jit_ok = true };
    uint32_t k = 0;
    p.code[k++] = VFM_PUSH; put64(p.code+k, 10); k += 8;
    p.code[k++] = VFM_PUSH; put64(p.code+k, 32); k += 8;
    p.code[k++] = VFM_ADD;
    p.code[k++] = VFM_RET;
    p.len = k; return p;
}
// dst-port filter (LD16 -> JIT declines -> interpreter). Accept iff port == 443.
static prog_t make_port443(void) {
    prog_t p = { .name = "port443", .jit_ok = false };
    uint8_t c[] = {
        VFM_LD16, 36, 0x00,
        VFM_PUSH, 0xBB,0x01,0,0,0,0,0,0,      // 443
        VFM_JEQ, 0x0A, 0x00,                  // == -> +10 (accept)
        VFM_PUSH, 0,0,0,0,0,0,0,0, VFM_RET,   // drop
        VFM_PUSH, 1,0,0,0,0,0,0,0, VFM_RET    // accept
    };
    memcpy(p.code, c, sizeof(c)); p.len = sizeof(c); return p;
}
// proto filter (LD8 -> JIT declines). Accept iff IP proto byte (offset 23) == 6.
static prog_t make_proto_tcp(void) {
    prog_t p = { .name = "proto_tcp", .jit_ok = false };
    uint8_t c[] = {
        VFM_LD8, 23, 0x00,
        VFM_PUSH, 6,0,0,0,0,0,0,0,
        VFM_JEQ, 0x0A, 0x00,
        VFM_PUSH, 0,0,0,0,0,0,0,0, VFM_RET,
        VFM_PUSH, 1,0,0,0,0,0,0,0, VFM_RET
    };
    memcpy(p.code, c, sizeof(c)); p.len = sizeof(c); return p;
}
// IPv6 128-bit compare (LD128/EQ128 -> JIT declines). Accept iff the 16 bytes at
// offset 22 equal the 16 bytes at offset 38.
static prog_t make_ipv6_eq(void) {
    prog_t p = { .name = "ipv6_eq", .jit_ok = false };
    uint8_t c[] = {
        VFM_LD128, 22, 0x00,
        VFM_LD128, 38, 0x00,
        VFM_EQ128,
        VFM_RET
    };
    memcpy(p.code, c, sizeof(c)); p.len = sizeof(c); return p;
}

// ---------------------------------------------------------------------------
// Oracle: interpreter-only single-core result for one (program, packet).
// ---------------------------------------------------------------------------
static int oracle(const uint8_t *prog, uint32_t plen, const uint8_t *pkt, uint16_t len) {
    vfm_state_t *vm = vfm_create();
    vm->cold.jit_enabled = false;
    if (vfm_load_program(vm, prog, plen) != VFM_SUCCESS) { vfm_destroy(vm); return -1; }
    int r = vfm_execute(vm, pkt, len);
    vfm_destroy(vm);
    return (r > 0) ? 1 : 0;
}

// Build a packet set with a deterministic mix (ports, protos, IPv6 bytes).
#define NPKT 500
static uint8_t packets[NPKT][64];
static const uint8_t *pkt_ptrs[NPKT];
static uint16_t pkt_lens[NPKT];

static void build_packets(void) {
    for (int i = 0; i < NPKT; i++) {
        memset(packets[i], 0, 64);
        // dst port at 36-37: half get 443, others get a varying port
        if (i % 2 == 0) { packets[i][36] = 0x01; packets[i][37] = 0xBB; }
        else            { packets[i][36] = (uint8_t)(i & 0xFF); packets[i][37] = (uint8_t)i; }
        // proto at 23: every third is TCP (6), else 17 (UDP)
        packets[i][23] = (i % 3 == 0) ? 6 : 17;
        // IPv6 region: make offsets 22 and 38 equal for every fourth packet
        for (int b = 0; b < 16; b++) {
            packets[i][22 + b] = (uint8_t)(i + b);
            packets[i][38 + b] = (i % 4 == 0) ? (uint8_t)(i + b) : (uint8_t)(i + b + 1);
        }
        pkt_ptrs[i] = packets[i];
        pkt_lens[i] = 64;
    }
}

// Run one program over `count` packets on `num_cores` and check vs oracle.
static void run_correctness(prog_t *p, uint32_t num_cores, uint32_t count) {
    vfm_multicore_state_t *mc = mc_new(num_cores);
    CHECK(mc != NULL, "multicore_create");
    if (!mc) return;

    int rc = vfm_multicore_load_program(mc, p->code, p->len);
    CHECK(rc == VFM_SUCCESS, "multicore_load_program");

    // JIT-active gate: a jit_ok program MUST have a non-NULL shared page when
    // the JIT is available; a declined program MUST have left it NULL. (Skipped
    // under TSan, where the JIT is intentionally disabled.)
#if defined(__aarch64__) && !defined(VFM_TSAN_NO_JIT)
    extern bool vfm_jit_available_arm64(void);
    if (vfm_jit_available_arm64()) {
        if (p->jit_ok) CHECK(mc->shared->jit_code != NULL, "jit_ok program must compile");
        else           CHECK(mc->shared->jit_code == NULL, "declined program must stay NULL");
    }
#endif
    // Every core's VM must agree with the shared publication.
    for (uint32_t c = 0; c < mc->num_cores; c++) {
        CHECK(mc->cores[c]->vm != NULL, "core vm created");
        CHECK(mc->cores[c]->vm->cold.jit_code == mc->shared->jit_code, "core jit_code published");
    }

    uint8_t results[NPKT];
    memset(results, 0xEE, sizeof(results));
    vfm_batch_t batch = { .packets = pkt_ptrs, .lengths = pkt_lens, .results = results, .count = count };
    rc = vfm_multicore_execute_batch(mc, &batch);
    CHECK(rc == VFM_SUCCESS, "execute_batch");

    int mism = 0, accepts = 0;
    for (uint32_t i = 0; i < count; i++) {
        int want = oracle(p->code, p->len, pkt_ptrs[i], pkt_lens[i]);
        if ((int)results[i] != want) mism++;
        accepts += want;
    }
    if (mism) {
        printf("   FAIL: %s cores=%u count=%u -> %d mismatches vs oracle\n",
               p->name, num_cores, count, mism);
        g_failures++;
    } else {
        printf("   OK:   %s cores=%u count=%u (%d accept / %u drop)\n",
               p->name, num_cores, count, accepts, count - accepts);
    }
    vfm_multicore_destroy(mc);
}

static void test_correctness(void) {
    printf("\n== Correctness vs interpreter oracle ==\n");
    prog_t progs[] = { make_accept_all(), make_drop_all(), make_add(),
                       make_port443(), make_proto_tcp(), make_ipv6_eq() };
    uint32_t cores[] = { 1, 2, 8 };
    // counts chosen to NOT divide evenly by 8/2, and to be smaller than cores:
    uint32_t counts[] = { 1, 3, 7, 50, 100, 333, NPKT };
    for (size_t pi = 0; pi < sizeof(progs)/sizeof(progs[0]); pi++) {
        for (size_t ci = 0; ci < sizeof(cores)/sizeof(cores[0]); ci++) {
            for (size_t ni = 0; ni < sizeof(counts)/sizeof(counts[0]); ni++) {
                run_correctness(&progs[pi], cores[ci], counts[ni]);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Recompilation: lower the threshold, feed > threshold packets across several
// batches, assert the adaptive recompile fired and results still match.
// ---------------------------------------------------------------------------
static void test_recompile(void) {
    printf("\n== Recompilation triggering ==\n");
    prog_t p = make_add();  // JIT'd -> there IS a live page to swap
    vfm_multicore_state_t *mc = mc_new(8);
    CHECK(mc != NULL, "create"); if (!mc) return;
    CHECK(vfm_multicore_load_program(mc, p.code, p.len) == VFM_SUCCESS, "load");

    void *initial = mc->shared->jit_code;
#ifdef __aarch64__
    extern bool vfm_jit_available_arm64(void);
    bool have_jit = vfm_jit_available_arm64();
#else
    bool have_jit = (initial != NULL);
#endif
    CHECK(!have_jit || initial != NULL, "initial jit page present");

    mc->shared->recompilation_threshold = 100;  // public struct field

    uint8_t results[NPKT];
    vfm_batch_t batch = { .packets = pkt_ptrs, .lengths = pkt_lens, .results = results, .count = 40 };
    // 5 batches x 40 = 200 executions > 100 threshold (and < 5000 so the
    // threshold-adjuster does not move the goalposts; the primary trigger fires).
    for (int b = 0; b < 5; b++) {
        CHECK(vfm_multicore_execute_batch(mc, &batch) == VFM_SUCCESS, "batch");
    }

    // Capture the recompiled page NOW, before any further batch can trigger a
    // second recompile (whose mmap may legitimately reuse the freed initial
    // address, which would make a later == comparison misleading).
    void *recompiled = mc->shared->jit_code;
    CHECK(mc->shared->opt_level == VFM_JIT_OPT_ADAPTIVE, "opt_level -> ADAPTIVE");
    if (have_jit) {
        CHECK(recompiled != NULL, "recompiled page non-NULL");
        CHECK(recompiled != initial, "jit_code pointer changed");
        for (uint32_t c = 0; c < mc->num_cores; c++) {
            CHECK(mc->cores[c]->vm->cold.jit_code == recompiled,
                  "every core re-points to the new page");
        }
    }
    // Verify results still correct, without re-triggering: raise the threshold
    // so this batch does not recompile again.
    mc->shared->recompilation_threshold = 100000000;
    CHECK(vfm_multicore_execute_batch(mc, &batch) == VFM_SUCCESS, "post-recompile batch");
    CHECK(mc->shared->jit_code == recompiled, "page stable when no trigger");
    int mism = 0;
    for (uint32_t i = 0; i < batch.count; i++)
        if ((int)results[i] != oracle(p.code, p.len, pkt_ptrs[i], pkt_lens[i])) mism++;
    CHECK(mism == 0, "post-recompile results match oracle");
    printf("   recompile: opt_level=%d initial=%p recompiled=%p\n",
           mc->shared->opt_level, initial, recompiled);
    vfm_multicore_destroy(mc);
}

// Declined recompile (UAF regression): a program with an unimplemented opcode
// never has a live page; the recompile must fire, DECLINE, and leave everything
// valid (no free of NULL-with-wrong-size, no core dangling), results correct.
static void test_decline_recompile(void) {
    printf("\n== Declined recompile (UAF regression) ==\n");
    prog_t p = make_port443();  // LD16 -> always declines
    vfm_multicore_state_t *mc = mc_new(8);
    CHECK(mc != NULL, "create"); if (!mc) return;
    CHECK(vfm_multicore_load_program(mc, p.code, p.len) == VFM_SUCCESS, "load");
    CHECK(mc->shared->jit_code == NULL, "declined program: no shared page");
    mc->shared->recompilation_threshold = 50;

    uint8_t results[NPKT];
    vfm_batch_t batch = { .packets = pkt_ptrs, .lengths = pkt_lens, .results = results, .count = 40 };
    for (int b = 0; b < 6; b++)  // 240 > 50 -> recompile attempts fire repeatedly
        CHECK(vfm_multicore_execute_batch(mc, &batch) == VFM_SUCCESS, "batch");

    CHECK(mc->shared->jit_code == NULL, "declined recompile leaves page NULL (no UAF)");
    for (uint32_t c = 0; c < mc->num_cores; c++)
        CHECK(mc->cores[c]->vm->cold.jit_code == NULL, "cores still NULL (interpreter)");
    int mism = 0;
    for (uint32_t i = 0; i < batch.count; i++)
        if ((int)results[i] != oracle(p.code, p.len, pkt_ptrs[i], pkt_lens[i])) mism++;
    CHECK(mism == 0, "results still correct through declined recompiles");
    printf("   declined recompile survived; results correct\n");
    vfm_multicore_destroy(mc);
}

// Two concurrent instances with different thresholds: proves counters are
// per-instance (the old function-local static was shared across all handles).
static void test_two_instances(void) {
    printf("\n== Two concurrent mc_vm instances ==\n");
    prog_t p = make_add();
    vfm_multicore_state_t *a = mc_new(4);
    vfm_multicore_state_t *b = mc_new(4);
    CHECK(a && b, "create two"); if (!a || !b) return;
    CHECK(vfm_multicore_load_program(a, p.code, p.len) == VFM_SUCCESS, "load a");
    CHECK(vfm_multicore_load_program(b, p.code, p.len) == VFM_SUCCESS, "load b");
    a->shared->recompilation_threshold = 100;          // a WILL recompile
    b->shared->recompilation_threshold = 100000000;    // b will NOT

    uint8_t ra[NPKT], rb[NPKT];
    vfm_batch_t ba = { pkt_ptrs, pkt_lens, ra, 60 };
    vfm_batch_t bb = { pkt_ptrs, pkt_lens, rb, 60 };
    for (int i = 0; i < 4; i++) {
        CHECK(vfm_multicore_execute_batch(a, &ba) == VFM_SUCCESS, "batch a");
        CHECK(vfm_multicore_execute_batch(b, &bb) == VFM_SUCCESS, "batch b");
    }
    CHECK(a->shared->opt_level == VFM_JIT_OPT_ADAPTIVE, "a recompiled");
    CHECK(b->shared->opt_level != VFM_JIT_OPT_ADAPTIVE, "b did NOT recompile (per-instance counter)");
    printf("   a->total=%llu b->total=%llu a->opt=%d b->opt=%d\n",
           (unsigned long long)a->shared->total_executions,
           (unsigned long long)b->shared->total_executions,
           a->shared->opt_level, b->shared->opt_level);
    vfm_multicore_destroy(a);
    vfm_multicore_destroy(b);
}

// Hundreds of back-to-back batches on 8 cores -- the deadlock regression. The
// watchdog thread fails the run if this wedges.
static void test_no_deadlock(void) {
    printf("\n== No-deadlock stress (hundreds of batches x 8 cores) ==\n");
    prog_t p = make_proto_tcp();
    vfm_multicore_state_t *mc = mc_new(8);
    CHECK(mc != NULL, "create"); if (!mc) return;
    CHECK(vfm_multicore_load_program(mc, p.code, p.len) == VFM_SUCCESS, "load");

    uint8_t results[NPKT];
    int mism = 0;
    for (int b = 0; b < 500; b++) {
        uint32_t count = 1 + (uint32_t)(b % NPKT);  // varying, includes < num_cores
        vfm_batch_t batch = { pkt_ptrs, pkt_lens, results, count };
        if (vfm_multicore_execute_batch(mc, &batch) != VFM_SUCCESS) { g_failures++; break; }
        // Spot-check a few packets each batch.
        for (uint32_t i = 0; i < count && i < 5; i++)
            if ((int)results[i] != oracle(p.code, p.len, pkt_ptrs[i], pkt_lens[i])) mism++;
    }
    CHECK(mism == 0, "stress results match oracle");
    printf("   500 batches completed without deadlock\n");
    vfm_multicore_destroy(mc);
}

// Program-lifetime: the caller's program buffer is freed between batches. Works
// only because load_program copies the program into shared ownership.
static void test_program_lifetime(void) {
    printf("\n== Program-lifetime (freed caller buffer) ==\n");
    prog_t base = make_add();
    uint8_t *heap = malloc(base.len);
    memcpy(heap, base.code, base.len);
    vfm_multicore_state_t *mc = mc_new(4);
    CHECK(mc != NULL, "create"); if (!mc) { free(heap); return; }
    CHECK(vfm_multicore_load_program(mc, heap, base.len) == VFM_SUCCESS, "load");
    free(heap);  // caller buffer gone; shared copy must keep everything valid

    uint8_t results[NPKT];
    vfm_batch_t batch = { pkt_ptrs, pkt_lens, results, 120 };
    int mism = 0;
    for (int b = 0; b < 3; b++) {
        CHECK(vfm_multicore_execute_batch(mc, &batch) == VFM_SUCCESS, "batch after free");
        for (uint32_t i = 0; i < batch.count; i++)
            if ((int)results[i] != oracle(base.code, base.len, pkt_ptrs[i], pkt_lens[i])) mism++;
    }
    CHECK(mism == 0, "results correct after caller buffer freed");
    printf("   program-lifetime OK\n");
    vfm_multicore_destroy(mc);
}

int main(void) {
    printf("VFM Multicore Adaptive-JIT Tests\n");
    printf("================================\n");

#ifdef __aarch64__
    extern bool vfm_jit_available_arm64(void);
    printf("ARM64 JIT available: %s\n", vfm_jit_available_arm64() ? "YES" : "NO");
#endif

    int budget = 60;  // seconds
    pthread_t wd;
    pthread_create(&wd, NULL, watchdog, &budget);

    // Initialize the process-global JIT cache so compiled pages are installed
    // (mirrors the real embedding; without it single-core caching discards code).
    vfm_jit_cache_init(NULL);

    build_packets();

    test_correctness();
#ifndef VFM_TSAN_NO_JIT
    // JIT-lifecycle tests (recompile swap, decline, per-instance counters) need
    // the JIT enabled; they are covered under ASan. TSan runs the pure
    // concurrency + correctness paths with the JIT disabled.
    test_recompile();
    test_decline_recompile();
    test_two_instances();
#endif
    test_no_deadlock();
    test_program_lifetime();

    g_done = 1;
    pthread_join(wd, NULL);  // let the watchdog observe g_done and exit cleanly

    printf("\n================================\n");
    if (g_failures) {
        printf("FAILED: %d check(s) failed\n", g_failures);
        return 1;
    }
    printf("All multicore tests passed.\n");
    return 0;
}
