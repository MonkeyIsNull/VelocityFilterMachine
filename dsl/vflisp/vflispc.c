#include "vflisp_types.h"
#include "../../include/vfm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

// Function prototypes
int vfl_compile_file(const char *filename, uint8_t **bytecode, uint32_t *bytecode_len, char *error_msg, size_t error_msg_size);
int vfl_compile_string(const char *source, uint8_t **bytecode, uint32_t *bytecode_len, char *error_msg, size_t error_msg_size);
vfl_node_t* vfl_parse(const char *input);
vfl_node_t* vfl_parse_file(const char *filename);

// Usage information
static void print_usage(const char *program_name) {
    printf("VFLisp Compiler - Compile Lisp expressions to VFM bytecode\n\n");
    printf("Usage: %s [options] [input-file]\n\n", program_name);
    printf("Options:\n");
    printf("  -h, --help           Show this help message\n");
    printf("  -o, --output FILE    Output bytecode to FILE (default: stdout)\n");
    printf("  -a, --ast            Print AST instead of compiling\n");
    printf("  -d, --disasm         Disassemble bytecode after compilation\n");
    printf("  -t, --test           Test compilation with example packet\n");
    printf("  -v, --verbose        Verbose output\n");
    printf("  -e, --expression STR Compile expression from command line\n");
    printf("\nExamples:\n");
    printf("  %s -e '(= proto 6)'           # Compile inline expression\n", program_name);
    printf("  %s filter.vfl -o filter.bin   # Compile file to bytecode\n", program_name);
    printf("  %s -a filter.vfl              # Show AST for file\n", program_name);
    printf("  %s -d filter.vfl              # Compile and disassemble\n", program_name);
    printf("  %s -t filter.vfl              # Test with example packet\n", program_name);
    printf("\nSupported functions:\n");
    printf("  Arithmetic: +, -, *, /, %%\n");
    printf("  Comparison: =, !=, >, >=, <, <=\n");
    printf("  Logical: and, or, not\n");
    printf("  Bitwise: &, |, ^, <<, >>\n");
    printf("  Control: if\n");
    printf("\nSupported packet fields:\n");
    printf("  proto, src-ip, dst-ip, src-port, dst-port\n");
    printf("  ethertype, ip-len, tcp-flags\n");
}

// Write bytecode to file
static int write_bytecode(const char *filename, const uint8_t *bytecode, uint32_t bytecode_len) {
    FILE *file = stdout;
    
    if (filename) {
        file = fopen(filename, "wb");
        if (!file) {
            fprintf(stderr, "Error: Cannot open output file '%s'\n", filename);
            return -1;
        }
    }
    
    size_t written = fwrite(bytecode, 1, bytecode_len, file);
    if (written != bytecode_len) {
        fprintf(stderr, "Error: Failed to write complete bytecode\n");
        if (filename) fclose(file);
        return -1;
    }
    
    if (filename) {
        fclose(file);
        printf("Bytecode written to %s (%u bytes)\n", filename, bytecode_len);
    }
    
    return 0;
}

// Create a simple test packet (TCP SYN to port 80)
static void create_test_packet(uint8_t *packet, uint16_t *packet_len) {
    // Ethernet header (14 bytes)
    memset(packet, 0, 14);
    packet[12] = 0x08;  // EtherType: IPv4
    packet[13] = 0x00;
    
    // IP header (20 bytes)
    packet[14] = 0x45;  // Version 4, IHL 5
    packet[15] = 0x00;  // DSCP/ECN
    packet[16] = 0x00;  // Total length (will be filled)
    packet[17] = 0x3C;  // 60 bytes
    packet[18] = 0x12;  // Identification
    packet[19] = 0x34;
    packet[20] = 0x40;  // Flags (DF set)
    packet[21] = 0x00;  // Fragment offset
    packet[22] = 0x40;  // TTL
    packet[23] = 0x06;  // Protocol: TCP
    packet[24] = 0x00;  // Checksum (placeholder)
    packet[25] = 0x00;
    packet[26] = 0xC0;  // Source IP: 192.168.1.100
    packet[27] = 0xA8;
    packet[28] = 0x01;
    packet[29] = 0x64;
    packet[30] = 0x08;  // Dest IP: 8.8.8.8
    packet[31] = 0x08;
    packet[32] = 0x08;
    packet[33] = 0x08;
    
    // TCP header (20 bytes)
    packet[34] = 0x04;  // Source port: 1234
    packet[35] = 0xD2;
    packet[36] = 0x00;  // Dest port: 80
    packet[37] = 0x50;
    packet[38] = 0x00;  // Sequence number
    packet[39] = 0x00;
    packet[40] = 0x00;
    packet[41] = 0x01;
    packet[42] = 0x00;  // Acknowledgment number
    packet[43] = 0x00;
    packet[44] = 0x00;
    packet[45] = 0x00;
    packet[46] = 0x50;  // Data offset (5 words)
    packet[47] = 0x02;  // Flags: SYN
    packet[48] = 0x72;  // Window size
    packet[49] = 0x10;
    packet[50] = 0x00;  // Checksum (placeholder)
    packet[51] = 0x00;
    packet[52] = 0x00;  // Urgent pointer
    packet[53] = 0x00;
    
    *packet_len = 54;
}

// Test bytecode with example packet
static int test_bytecode(const uint8_t *bytecode, uint32_t bytecode_len, int verbose) {
    printf("Testing bytecode with example packet...\n");
    
    // Create test packet
    uint8_t packet[64];
    uint16_t packet_len;
    create_test_packet(packet, &packet_len);
    
    if (verbose) {
        printf("Test packet (%d bytes):\n", packet_len);
        for (int i = 0; i < packet_len; i++) {
            printf("%02x ", packet[i]);
            if ((i + 1) % 16 == 0) printf("\n");
        }
        if (packet_len % 16 != 0) printf("\n");
        printf("\n");
    }
    
    // Create VM and load program
    vfm_state_t *vm = vfm_create();
    if (!vm) {
        fprintf(stderr, "Error: Failed to create VM\n");
        return -1;
    }
    
    if (vfm_load_program(vm, bytecode, bytecode_len) < 0) {
        fprintf(stderr, "Error: Failed to load program\n");
        vfm_destroy(vm);
        return -1;
    }
    
    // Execute filter
    int result = vfm_execute(vm, packet, packet_len);
    
    if (result < 0) {
        fprintf(stderr, "Error: Filter execution failed: %s\n", vfm_error_string(result));
        vfm_destroy(vm);
        return -1;
    }
    
    printf("Filter result: %s (%d)\n", result ? "ACCEPT" : "DROP", result);
    
    if (verbose) {
        printf("Filter executed successfully\n");
    }
    
    vfm_destroy(vm);
    return 0;
}

int main(int argc, char *argv[]) {
    int opt;
    char *output_file = NULL;
    char *expression = NULL;
    int show_ast = 0;
    int disassemble = 0;
    int test_mode = 0;
    int verbose = 0;
    
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"output", required_argument, 0, 'o'},
        {"ast", no_argument, 0, 'a'},
        {"disasm", no_argument, 0, 'd'},
        {"test", no_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"expression", required_argument, 0, 'e'},
        {0, 0, 0, 0}
    };
    
    while ((opt = getopt_long(argc, argv, "ho:adtve:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 'o':
                output_file = optarg;
                break;
            case 'a':
                show_ast = 1;
                break;
            case 'd':
                disassemble = 1;
                break;
            case 't':
                test_mode = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'e':
                expression = optarg;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Determine input source
    const char *input_file = NULL;
    if (optind < argc) {
        input_file = argv[optind];
    }
    
    if (!expression && !input_file) {
        fprintf(stderr, "Error: No input specified. Use -e for expression or provide input file.\n");
        print_usage(argv[0]);
        return 1;
    }
    
    if (expression && input_file) {
        fprintf(stderr, "Error: Cannot specify both -e and input file.\n");
        return 1;
    }
    
    // Parse input
    vfl_node_t *ast = NULL;
    if (expression) {
        if (verbose) printf("Parsing expression: %s\n", expression);
        ast = vfl_parse(expression);
    } else {
        if (verbose) printf("Parsing file: %s\n", input_file);
        ast = vfl_parse_file(input_file);
    }
    
    if (!ast) {
        fprintf(stderr, "Error: Failed to parse input\n");
        return 1;
    }
    
    // Show AST if requested
    if (show_ast) {
        printf("Abstract Syntax Tree:\n");
        vfl_node_print(ast, 0);
        vfl_node_destroy(ast);
        return 0;
    }
    
    // Compile to bytecode
    uint8_t *bytecode = NULL;
    uint32_t bytecode_len = 0;
    char error_msg[256];
    
    if (verbose) printf("Compiling to bytecode...\n");
    
    int result = vfl_compile(ast, &bytecode, &bytecode_len, error_msg, sizeof(error_msg));
    vfl_node_destroy(ast);
    
    if (result < 0) {
        fprintf(stderr, "Error: Compilation failed: %s\n", error_msg);
        return 1;
    }
    
    if (verbose) printf("Compilation successful (%u bytes)\n", bytecode_len);
    
    // Verify bytecode
    if (vfm_verify(bytecode, bytecode_len) < 0) {
        fprintf(stderr, "Error: Bytecode verification failed\n");
        free(bytecode);
        return 1;
    }
    
    if (verbose) printf("Bytecode verification passed\n");
    
    // Disassemble if requested
    if (disassemble) {
        printf("Disassembly:\n");
        char disasm_output[4096];
        vfm_disassemble(bytecode, bytecode_len, disasm_output, sizeof(disasm_output));
        printf("%s\n", disasm_output);
    }
    
    // Test if requested
    if (test_mode) {
        if (test_bytecode(bytecode, bytecode_len, verbose) < 0) {
            free(bytecode);
            return 1;
        }
    }
    
    // Write output
    if (!test_mode && !disassemble) {
        if (write_bytecode(output_file, bytecode, bytecode_len) < 0) {
            free(bytecode);
            return 1;
        }
    }
    
    free(bytecode);
    return 0;
}