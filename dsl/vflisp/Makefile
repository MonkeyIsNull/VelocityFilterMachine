CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2 -g
LDFLAGS = -L../../ -lvfm

# Source files
SOURCES = vflisp_parser.c vflisp_compile.c vflispc.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = vflispc

# VFM library dependency
VFM_LIB = ../../libvfm.a

# Default target
all: $(TARGET)

# Build the VFLisp compiler
$(TARGET): $(OBJECTS) $(VFM_LIB)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

# Build object files
%.o: %.c vflisp_types.h
	$(CC) $(CFLAGS) -c $< -o $@

# Ensure VFM library is built
$(VFM_LIB):
	$(MAKE) -C ../../ libvfm.a

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)

# Install to system
install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/

# Uninstall from system
uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)

# Test examples
test: $(TARGET)
	@echo "Testing VFLisp examples..."
	@for example in examples/*.vfl; do \
		echo "Testing $$example..."; \
		./$(TARGET) -t "$$example" || exit 1; \
	done
	@echo "All tests passed!"

# Show AST for all examples
show-ast: $(TARGET)
	@for example in examples/*.vfl; do \
		echo "AST for $$example:"; \
		./$(TARGET) -a "$$example"; \
		echo; \
	done

# Compile all examples to bytecode
compile-examples: $(TARGET)
	@mkdir -p examples/compiled
	@for example in examples/*.vfl; do \
		base=$$(basename "$$example" .vfl); \
		echo "Compiling $$example..."; \
		./$(TARGET) "$$example" -o "examples/compiled/$$base.bin"; \
	done

# Run benchmarks
benchmark: $(TARGET)
	@echo "Running VFLisp benchmarks..."
	@time ./$(TARGET) -t examples/tcp_filter.vfl
	@time ./$(TARGET) -t examples/web_filter.vfl
	@time ./$(TARGET) -t examples/complex_filter.vfl

# Help
help:
	@echo "VFLisp Makefile"
	@echo "Available targets:"
	@echo "  all            - Build the VFLisp compiler"
	@echo "  clean          - Clean build artifacts"
	@echo "  install        - Install to /usr/local/bin"
	@echo "  uninstall      - Remove from /usr/local/bin"
	@echo "  test           - Test all examples"
	@echo "  show-ast       - Show AST for all examples"
	@echo "  compile-examples - Compile all examples to bytecode"
	@echo "  benchmark      - Run performance benchmarks"
	@echo "  help           - Show this help"

.PHONY: all clean install uninstall test show-ast compile-examples benchmark help