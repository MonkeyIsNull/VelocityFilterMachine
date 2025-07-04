# Velocity Filter Machine (VFM) Makefile

CC = gcc
CFLAGS = -Wall -Wextra -O3 -march=native -I./include -I./src
LDFLAGS = 
DEBUG_FLAGS = -g -O0 -DDEBUG
TEST_FLAGS = -I./test

# Platform-specific optimizations
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # macOS optimizations
    CFLAGS += -framework Accelerate
    ifdef APPLE_SILICON
        # Apple Silicon specific flags
        CFLAGS += -mcpu=apple-m1 -mtune=native
    endif
    # Use clang on macOS for better optimization
    CC = clang
    CFLAGS += -fvectorize -fslp-vectorize
else ifeq ($(UNAME_S),Linux)
    # Linux optimizations
    CFLAGS += -march=native -mtune=native
    LDFLAGS += -lpthread
endif

# Enable link-time optimization
CFLAGS += -flto
LDFLAGS += -flto

# Source files
SRC_DIR = src
TOOL_DIR = tools
TEST_DIR = test
BENCH_DIR = bench

# Core library sources
LIB_SRCS = $(SRC_DIR)/vfm.c \
           $(SRC_DIR)/verifier.c \
           $(SRC_DIR)/compiler.c

# Platform-specific JIT sources
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),x86_64)
    LIB_SRCS += $(SRC_DIR)/jit_x86_64.c
else ifeq ($(UNAME_M),aarch64)
    LIB_SRCS += $(SRC_DIR)/jit_arm64.c
endif

LIB_OBJS = $(LIB_SRCS:.c=.o)

# Tool sources
TOOL_SRCS = $(TOOL_DIR)/vfm-asm.c \
            $(TOOL_DIR)/vfm-dis.c \
            $(TOOL_DIR)/vfm-test.c

TOOLS = $(TOOL_SRCS:.c=)

# Test sources
TEST_SRCS = $(TEST_DIR)/test_vfm.c
TEST_BINS = $(TEST_SRCS:.c=)

# Benchmark sources
BENCH_SRCS = $(BENCH_DIR)/bench.c
BENCH_BINS = $(BENCH_SRCS:.c=)

# Targets
.PHONY: all clean debug test bench tools

all: libvfm.a tools

# Static library
libvfm.a: $(LIB_OBJS)
	ar rcs $@ $^

# Object files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Tools
tools: $(TOOLS)

$(TOOL_DIR)/vfm-asm: $(TOOL_DIR)/vfm-asm.c libvfm.a
	$(CC) $(CFLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)

$(TOOL_DIR)/vfm-dis: $(TOOL_DIR)/vfm-dis.c libvfm.a
	$(CC) $(CFLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)

$(TOOL_DIR)/vfm-test: $(TOOL_DIR)/vfm-test.c libvfm.a
	$(CC) $(CFLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)

# Tests
test: $(TEST_BINS)
	./$(TEST_DIR)/test_vfm

$(TEST_DIR)/test_vfm: $(TEST_DIR)/test_vfm.c libvfm.a
	$(CC) $(CFLAGS) $(TEST_FLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)

# Benchmarks
bench: $(BENCH_BINS)
	./$(BENCH_DIR)/bench

$(BENCH_DIR)/bench: $(BENCH_DIR)/bench.c libvfm.a
	$(CC) $(CFLAGS) $< -o $@ -L. -lvfm $(LDFLAGS)

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: clean all

# Clean
clean:
	rm -f $(LIB_OBJS) libvfm.a
	rm -f $(TOOLS)
	rm -f $(TEST_BINS)
	rm -f $(BENCH_BINS)

# Install (optional)
PREFIX ?= /usr/local
install: libvfm.a
	install -d $(PREFIX)/lib
	install -d $(PREFIX)/include
	install -d $(PREFIX)/bin
	install -m 644 libvfm.a $(PREFIX)/lib/
	install -m 644 include/vfm.h $(PREFIX)/include/
	install -m 755 $(TOOLS) $(PREFIX)/bin/

uninstall:
	rm -f $(PREFIX)/lib/libvfm.a
	rm -f $(PREFIX)/include/vfm.h
	rm -f $(PREFIX)/bin/vfm-asm
	rm -f $(PREFIX)/bin/vfm-dis
	rm -f $(PREFIX)/bin/vfm-test