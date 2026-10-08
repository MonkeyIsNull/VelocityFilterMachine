# Velocity Filter Machine (VFM) Makefile

CC = gcc
# Portable by default: no -march=native, so binaries run on any CPU of the
# target architecture (important for CI and for shipping release binaries).
# Opt into native-CPU tuning with `make NATIVE=1` for a faster but
# non-portable build that may SIGILL if run on a different/older CPU.
CFLAGS = -Wall -Wextra -O3 -I./include -I./src
LDFLAGS =
DEBUG_FLAGS = -g -O0 -DDEBUG
TEST_FLAGS = -I./test

# Native-CPU tuning (opt-in, non-portable)
ifdef NATIVE
    CFLAGS += -march=native -mtune=native
endif

# Platform-specific optimizations
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS optimizations
    LDFLAGS += -framework Accelerate
    ifdef APPLE_SILICON
        # Apple Silicon specific flags (opt-in, non-portable)
        CFLAGS += -mcpu=apple-m1
    endif
    # Use clang on macOS for better optimization
    CC = clang
    CFLAGS += -fvectorize -fslp-vectorize
    
    # JIT support requires proper entitlements on macOS
    CODESIGN = codesign
    ENTITLEMENTS = entitlements.plist
    
    # Check if we have a valid signing identity
    SIGNING_IDENTITY := $(shell security find-identity -v -p codesigning 2>/dev/null | grep "Developer ID Application" | head -1 | cut -d'"' -f2)
    ifeq ($(SIGNING_IDENTITY),)
        # Fall back to ad-hoc signing for development
        SIGNING_IDENTITY = -
    endif
else ifeq ($(UNAME_S),Linux)
    # Linux optimizations (native tuning is opt-in via NATIVE=1, handled above)
    LDFLAGS += -lpthread
endif

# JIT cache requires pthread on all platforms
LDFLAGS += -lpthread

# Enable link-time optimization
CFLAGS += -flto
LDFLAGS += -flto

# Source files
SRC_DIR = src
TOOL_DIR = tools
TEST_DIR = test
BENCH_DIR = bench
VFLISP_DIR = dsl/vflisp

# Core library sources
LIB_SRCS = $(SRC_DIR)/vfm.c \
           $(SRC_DIR)/vfm_jit_cache.c \
           $(SRC_DIR)/verifier.c \
           $(SRC_DIR)/compiler.c \
           $(SRC_DIR)/stubs.c

# Platform-specific JIT sources
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
    LIB_SRCS += $(SRC_DIR)/jit_x86_64.c
else ifneq ($(filter $(UNAME_M),aarch64 arm64),)
    LIB_SRCS += $(SRC_DIR)/jit_arm64.c
endif

LIB_OBJS = $(LIB_SRCS:.c=.o)

# VFLisp sources
VFLISP_SRCS = $(VFLISP_DIR)/vflisp_parser.c \
              $(VFLISP_DIR)/vflisp_compile.c \
              $(VFLISP_DIR)/vflisp_util.c

VFLISP_OBJS = $(VFLISP_SRCS:.c=.o)

# Tool sources
TOOL_SRCS = $(TOOL_DIR)/vfm-asm.c \
            $(TOOL_DIR)/vfm-dis.c \
            $(TOOL_DIR)/vfm-test.c

TOOLS = $(TOOL_SRCS:.c=)

# VFLisp compiler
VFLISPC = $(VFLISP_DIR)/vflispc

# Test sources
TEST_SRCS = $(TEST_DIR)/test_vfm.c $(TEST_DIR)/jit_test.c $(TEST_DIR)/test_multicore.c
TEST_BINS = $(TEST_SRCS:.c=)

# Sources needed to build sanitizer test binaries directly (no static lib, so
# the sanitizer instruments the library too).
SAN_SRCS = $(SRC_DIR)/vfm.c $(SRC_DIR)/vfm_jit_cache.c $(SRC_DIR)/verifier.c \
           $(SRC_DIR)/compiler.c $(SRC_DIR)/stubs.c \
           $(VFLISP_DIR)/vflisp_parser.c $(VFLISP_DIR)/vflisp_compile.c \
           $(VFLISP_DIR)/vflisp_util.c
ifeq ($(UNAME_M),x86_64)
    SAN_SRCS += $(SRC_DIR)/jit_x86_64.c
else ifneq ($(filter $(UNAME_M),aarch64 arm64),)
    SAN_SRCS += $(SRC_DIR)/jit_arm64.c
endif

# Benchmark sources
BENCH_SRCS = $(BENCH_DIR)/bench.c
BENCH_BINS = $(BENCH_SRCS:.c=)

# Targets
.PHONY: all clean debug test bench tools vflisp

all: libvfm.a tools vflisp

# Static library
libvfm.a: $(LIB_OBJS) $(VFLISP_OBJS)
	ar rcs $@ $^

# Object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Tools
tools: $(TOOLS)

$(TOOL_DIR)/vfm-asm: $(TOOL_DIR)/vfm-asm.c libvfm.a
	$(CC) $(CFLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	@echo "Code signing $@ for JIT support..."
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@ || true
endif

$(TOOL_DIR)/vfm-dis: $(TOOL_DIR)/vfm-dis.c libvfm.a
	$(CC) $(CFLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	@echo "Code signing $@ for JIT support..."
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@ || true
endif

$(TOOL_DIR)/vfm-test: $(TOOL_DIR)/vfm-test.c libvfm.a
	$(CC) $(CFLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	@echo "Code signing $@ for JIT support..."
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@ || true
endif

# VFLisp
vflisp: $(VFLISPC)

$(VFLISPC): $(VFLISP_DIR)/vflispc.c $(VFLISP_OBJS) libvfm.a
	$(CC) $(CFLAGS) -I$(VFLISP_DIR) $< $(VFLISP_OBJS) -o $@ -L. -lvfm $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	@echo "Code signing $@ for JIT support..."
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@ || true
endif

$(VFLISP_DIR)/%.o: $(VFLISP_DIR)/%.c
	$(CC) $(CFLAGS) -I$(VFLISP_DIR) -c $< -o $@

# Tests
test: $(TEST_BINS)
	@echo "=== Running VFM unit tests ==="
	./$(TEST_DIR)/test_vfm
	@echo ""
	@echo "=== Running VFM JIT tests ==="
	./$(TEST_DIR)/jit_test
	@echo ""
	@echo "=== Running VFM multicore tests ==="
	./$(TEST_DIR)/test_multicore

$(TEST_DIR)/test_vfm: $(TEST_DIR)/test_vfm.c libvfm.a
	$(CC) $(CFLAGS) $(TEST_FLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	@echo "Code signing $@ for JIT support..."
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@ || true
endif

# jit_test and test_multicore are JIT-CRITICAL: without the JIT entitlement,
# MAP_JIT silently yields an interpreter-only run and the tests cannot validate
# the JIT. We therefore sign with the ad-hoc fallback identity (SIGNING_IDENTITY
# becomes "-" when no Developer ID is found) and DO NOT swallow failure with
# `|| true` -- an unsigned JIT-critical binary must fail the build loudly.
$(TEST_DIR)/jit_test: $(TEST_DIR)/jit_test.c libvfm.a
	$(CC) $(CFLAGS) $(TEST_FLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	@echo "Code signing $@ for JIT support (JIT-critical, no || true)..."
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@
endif

$(TEST_DIR)/test_multicore: $(TEST_DIR)/test_multicore.c libvfm.a
	$(CC) $(CFLAGS) $(TEST_FLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	@echo "Code signing $@ for JIT support (JIT-critical, no || true)..."
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@
endif

# Sanitizer test targets for the multicore subsystem.
#   asan: JIT ENABLED -- exercises the recompile lifecycle (swap-on-success,
#         free-old-with-captured-size, declined recompile, borrowed-page teardown).
#   tsan: JIT DISABLED (VFM_TSAN_NO_JIT) -- TSan cannot instrument RX MAP_JIT
#         pages; this validates the barrier/completed_count/generation/
#         publication ordering and per-core stats.
.PHONY: test-asan test-tsan test-jit-asan
test-asan: $(TEST_DIR)/test_multicore_asan
	@echo "=== Running multicore tests under AddressSanitizer (JIT on) ==="
	ASAN_OPTIONS=detect_leaks=0 ./$(TEST_DIR)/test_multicore_asan

test-tsan: $(TEST_DIR)/test_multicore_tsan
	@echo "=== Running multicore tests under ThreadSanitizer (JIT off) ==="
	./$(TEST_DIR)/test_multicore_tsan

# jit-asan: JIT ENABLED -- exercises the single-core JIT cache teardown path
# (compile+store, cache-hit sharing, and the release/free ordering in
# vfm_destroy / vfm_load_program). Deterministically catches the cache-owned
# page UAF: the pre-fix teardown munmap'd a shared page, so the cache-hit VM
# executed freed memory and ASan reported SEGV.
test-jit-asan: $(TEST_DIR)/jit_test_asan
	@echo "=== Running JIT tests under AddressSanitizer (JIT on) ==="
	ASAN_OPTIONS=detect_leaks=0 ./$(TEST_DIR)/jit_test_asan

$(TEST_DIR)/test_multicore_asan: $(TEST_DIR)/test_multicore.c $(SAN_SRCS)
	$(CC) -fsanitize=address -g -O1 -I./include -I./src $(TEST_FLAGS) $^ -o $@ $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@
endif

$(TEST_DIR)/test_multicore_tsan: $(TEST_DIR)/test_multicore.c $(SAN_SRCS)
	$(CC) -fsanitize=thread -DVFM_TSAN_NO_JIT -g -O1 -I./include -I./src $(TEST_FLAGS) $^ -o $@ $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@
endif

$(TEST_DIR)/jit_test_asan: $(TEST_DIR)/jit_test.c $(SAN_SRCS)
	$(CC) -fsanitize=address -g -O1 -I./include -I./src $(TEST_FLAGS) $^ -o $@ $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@
endif

# Benchmarks
bench: $(BENCH_BINS)
	./$(BENCH_DIR)/bench

$(BENCH_DIR)/bench: $(BENCH_DIR)/bench.c libvfm.a
	$(CC) $(CFLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)
ifeq ($(UNAME_S),Darwin)
	@echo "Code signing $@ for JIT support..."
	$(CODESIGN) --entitlements $(ENTITLEMENTS) -s "$(SIGNING_IDENTITY)" $@ || true
endif

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all

# Clean
clean:
	rm -f $(LIB_OBJS) libvfm.a
	rm -f $(TOOLS)
	rm -f $(VFLISP_OBJS) $(VFLISPC)
	rm -f $(TEST_BINS)
	rm -f $(TEST_DIR)/test_multicore_asan $(TEST_DIR)/test_multicore_tsan
	rm -f $(TEST_DIR)/jit_test_asan
	rm -f $(BENCH_BINS)

# Install (optional)
PREFIX ?= /usr/local
install: libvfm.a tools vflisp
	install -d $(PREFIX)/lib
	install -d $(PREFIX)/include
	install -d $(PREFIX)/bin
	install -m 644 libvfm.a $(PREFIX)/lib/
	install -m 644 include/vfm.h $(PREFIX)/include/
	install -m 755 $(TOOLS) $(PREFIX)/bin/
	install -m 755 $(VFLISPC) $(PREFIX)/bin/

uninstall:
	rm -f $(PREFIX)/lib/libvfm.a
	rm -f $(PREFIX)/include/vfm.h
	rm -f $(PREFIX)/bin/vfm-asm
	rm -f $(PREFIX)/bin/vfm-dis
	rm -f $(PREFIX)/bin/vfm-test
	rm -f $(PREFIX)/bin/vflispc