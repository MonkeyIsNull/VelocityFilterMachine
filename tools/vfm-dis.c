#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include "../src/vfm.h"

// Disassembler configuration
typedef struct {
    const char *input_file;
    const char *output_file;
    FILE *output;
    int show_addresses;
    int show_hex;
    int verbose;
} disassembler_t;

// Print usage information
static void print_usage(const char *program_name) {
    printf("VFM Disassembler - Convert bytecode to assembly\n");
    printf("Usage: %s [options] <input.bin> [output.asm]\n", program_name);
    printf("\nOptions:\n");
    printf("  -a, --addresses    Show bytecode addresses\n");
    printf("  -x, --hex         Show hex dump alongside assembly\n");
    printf("  -v, --verbose     Verbose output\n");
    printf("  -h, --help        Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s filter.bin                     # Disassemble to stdout\n", program_name);
    printf("  %s filter.bin filter.asm          # Disassemble to file\n", program_name);
    printf("  %s -a -x filter.bin               # Show addresses and hex\n", program_name);
}

// Read little endian 16-bit value
static uint16_t read_u16_le(const uint8_t *data) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

// Read little endian 32-bit value
static uint32_t read_u32_le(const uint8_t *data) {
    return (uint32_t)data[0] | ((uint32_t)data[1] << 8) | 
           ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

// Read little endian 64-bit value
static uint64_t read_u64_le(const uint8_t *data) {
    return (uint64_t)read_u32_le(data) | ((uint64_t)read_u32_le(data + 4) << 32);
}

// Disassemble one instruction
static int disassemble_instruction(disassembler_t *dis, const uint8_t *program, 
                                   uint32_t program_size, uint32_t *pc) {
    if (*pc >= program_size) {
        return 0;  // End of program
    }
    
    uint8_t opcode = program[*pc];
    uint32_t start_pc = *pc;
    
    // Check for valid opcode
    if (opcode >= VFM_OPCODE_MAX) {
        if (dis->verbose) {
            fprintf(stderr, "Warning: Invalid opcode 0x%02x at address 0x%04x\n", 
                   opcode, *pc);
        }
        (*pc)++;
        return 1;
    }
    
    // Get instruction name
    const char *name = vfm_opcode_names[opcode];
    if (!name) {
        if (dis->verbose) {
            fprintf(stderr, "Warning: Unknown opcode %d at address 0x%04x\n", 
                   opcode, *pc);
        }
        (*pc)++;
        return 1;
    }
    
    // Calculate instruction size
    uint32_t insn_size = vfm_instruction_size(opcode);
    if (insn_size == 0) {
        if (dis->verbose) {
            fprintf(stderr, "Warning: Invalid instruction size for opcode %d at address 0x%04x\n", 
                   opcode, *pc);
        }
        (*pc)++;
        return 1;
    }
    
    // Check if we have enough bytes
    if (*pc + insn_size > program_size) {
        if (dis->verbose) {
            fprintf(stderr, "Warning: Truncated instruction at address 0x%04x\n", *pc);
        }
        return 0;
    }
    
    // Print address if requested
    if (dis->show_addresses) {
        fprintf(dis->output, "%04x:  ", start_pc);
    }
    
    // Print hex dump if requested
    if (dis->show_hex) {
        for (uint32_t i = 0; i < insn_size; i++) {
            fprintf(dis->output, "%02x ", program[*pc + i]);
        }
        // Pad to consistent width
        for (uint32_t i = insn_size; i < 9; i++) {
            fprintf(dis->output, "   ");
        }
    }
    
    // Print instruction name
    fprintf(dis->output, "%s", name);
    
    // Move past opcode
    (*pc)++;
    
    // Handle operands based on instruction format
    vfm_format_t format = vfm_opcode_format[opcode];
    switch (format) {
        case VFM_FMT_NONE:
            // No operands
            break;
            
        case VFM_FMT_IMM16: {
            if (*pc + 2 > program_size) {
                fprintf(dis->output, " <truncated>");
                return 0;
            }
            uint16_t value = read_u16_le(&program[*pc]);
            fprintf(dis->output, " %u", value);
            *pc += 2;
            break;
        }
        
        case VFM_FMT_IMM32: {
            if (*pc + 4 > program_size) {
                fprintf(dis->output, " <truncated>");
                return 0;
            }
            uint32_t value = read_u32_le(&program[*pc]);
            fprintf(dis->output, " %u", value);
            *pc += 4;
            break;
        }
        
        case VFM_FMT_IMM64: {
            if (*pc + 8 > program_size) {
                fprintf(dis->output, " <truncated>");
                return 0;
            }
            uint64_t value = read_u64_le(&program[*pc]);
            if (value <= 0xFFFFFFFF) {
                fprintf(dis->output, " %llu", value);
            } else {
                fprintf(dis->output, " 0x%llx", value);
            }
            *pc += 8;
            break;
        }
        
        case VFM_FMT_OFFSET16: {
            if (*pc + 2 > program_size) {
                fprintf(dis->output, " <truncated>");
                return 0;
            }
            int16_t offset = (int16_t)read_u16_le(&program[*pc]);
            uint32_t target = *pc + 2 + offset;
            
            // Show both relative offset and absolute target
            if (offset >= 0) {
                fprintf(dis->output, " +%d", offset);
            } else {
                fprintf(dis->output, " %d", offset);
            }
            
            if (dis->show_addresses) {
                fprintf(dis->output, " (0x%04x)", target);
            }
            
            *pc += 2;
            break;
        }
        
        default:
            fprintf(dis->output, " <unknown format>");
            return 0;
    }
    
    fprintf(dis->output, "\n");
    return 1;
}

// Load program from file
static int load_program(const char *filename, uint8_t **program, uint32_t *program_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s': %s\n", filename, strerror(errno));
        return -1;
    }
    
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    if (file_size < 0 || file_size > 0xFFFFFFFF) {
        fprintf(stderr, "Error: Invalid file size: %ld\n", file_size);
        fclose(file);
        return -1;
    }
    
    *program_size = (uint32_t)file_size;
    *program = malloc(*program_size);
    if (!*program) {
        fprintf(stderr, "Error: Cannot allocate memory for program\n");
        fclose(file);
        return -1;
    }
    
    size_t bytes_read = fread(*program, 1, *program_size, file);
    fclose(file);
    
    if (bytes_read != *program_size) {
        fprintf(stderr, "Error: Failed to read complete program file\n");
        free(*program);
        return -1;
    }
    
    return 0;
}

// Disassemble program
static int disassemble_program(disassembler_t *dis, const uint8_t *program, uint32_t program_size) {
    if (dis->verbose) {
        fprintf(dis->output, "; VFM Disassembly\n");
        fprintf(dis->output, "; Program size: %u bytes\n", program_size);
        fprintf(dis->output, "\n");
    }
    
    uint32_t pc = 0;
    uint32_t instruction_count = 0;
    
    while (pc < program_size) {
        if (!disassemble_instruction(dis, program, program_size, &pc)) {
            break;
        }
        instruction_count++;
    }
    
    if (dis->verbose) {
        fprintf(dis->output, "\n; Total instructions: %u\n", instruction_count);
        fprintf(dis->output, "; Program size: %u bytes\n", program_size);
    }
    
    return 0;
}

// Main function
int main(int argc, char *argv[]) {
    disassembler_t dis = {
        .input_file = NULL,
        .output_file = NULL,
        .output = stdout,
        .show_addresses = 0,
        .show_hex = 0,
        .verbose = 0
    };
    
    // Parse command line options
    static struct option long_options[] = {
        {"addresses", no_argument, 0, 'a'},
        {"hex", no_argument, 0, 'x'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "axvh", long_options, NULL)) != -1) {
        switch (opt) {
            case 'a':
                dis.show_addresses = 1;
                break;
            case 'x':
                dis.show_hex = 1;
                break;
            case 'v':
                dis.verbose = 1;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Check for required arguments
    if (optind >= argc) {
        fprintf(stderr, "Error: Input file required\n");
        print_usage(argv[0]);
        return 1;
    }
    
    dis.input_file = argv[optind];
    
    // Check for output file
    if (optind + 1 < argc) {
        dis.output_file = argv[optind + 1];
        dis.output = fopen(dis.output_file, "w");
        if (!dis.output) {
            fprintf(stderr, "Error: Cannot open output file '%s': %s\n", 
                   dis.output_file, strerror(errno));
            return 1;
        }
    }
    
    // Load program
    uint8_t *program = NULL;
    uint32_t program_size = 0;
    
    if (load_program(dis.input_file, &program, &program_size) != 0) {
        if (dis.output != stdout) {
            fclose(dis.output);
        }
        return 1;
    }
    
    if (dis.verbose) {
        fprintf(stderr, "Loaded program: %u bytes from '%s'\n", program_size, dis.input_file);
    }
    
    // Disassemble
    int result = disassemble_program(&dis, program, program_size);
    
    // Cleanup
    free(program);
    if (dis.output != stdout) {
        fclose(dis.output);
    }
    
    if (result == 0 && dis.verbose) {
        fprintf(stderr, "Disassembly complete\n");
    }
    
    return result;
}