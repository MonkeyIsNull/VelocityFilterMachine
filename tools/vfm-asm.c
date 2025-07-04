#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include "../src/vfm.h"
#include "../src/opcodes.h"

// Maximum program size
#define MAX_PROGRAM_SIZE 65536
#define MAX_LABELS 1000
#define MAX_LINE_LENGTH 1024
#define MAX_TOKEN_LENGTH 256

// Token types
typedef enum {
    TOKEN_EOF,
    TOKEN_IDENTIFIER,
    TOKEN_NUMBER,
    TOKEN_LABEL,
    TOKEN_COMMENT,
    TOKEN_NEWLINE
} token_type_t;

// Token structure
typedef struct {
    token_type_t type;
    char text[MAX_TOKEN_LENGTH];
    int line;
    int column;
} token_t;

// Label structure  
typedef struct {
    char name[MAX_TOKEN_LENGTH];
    uint32_t address;
    int line;
    int resolved;
} label_t;

// Forward reference structure
typedef struct {
    char name[MAX_TOKEN_LENGTH];
    uint32_t address;  // Address where the reference needs to be patched
    int line;
    int is_relative;   // 1 for relative jumps, 0 for absolute
} forward_ref_t;

// Assembler state
typedef struct {
    FILE *input;
    const char *filename;
    int line;
    int column;
    int error_count;
    
    // Output buffer
    uint8_t program[MAX_PROGRAM_SIZE];
    uint32_t program_size;
    
    // Labels and forward references
    label_t labels[MAX_LABELS];
    int label_count;
    forward_ref_t forward_refs[MAX_LABELS];
    int forward_ref_count;
    
    // Current token
    token_t current_token;
    int token_consumed;
} assembler_t;

// Opcode lookup table
typedef struct {
    const char *name;
    uint8_t opcode;
    vfm_format_t format;
} opcode_info_t;

static const opcode_info_t opcode_table[] = {
    {"LD8",        VFM_LD8,        VFM_FMT_IMM16},
    {"LD16",       VFM_LD16,       VFM_FMT_IMM16},
    {"LD32",       VFM_LD32,       VFM_FMT_IMM16},
    {"LD64",       VFM_LD64,       VFM_FMT_IMM16},
    {"PUSH",       VFM_PUSH,       VFM_FMT_IMM64},
    {"POP",        VFM_POP,        VFM_FMT_NONE},
    {"DUP",        VFM_DUP,        VFM_FMT_NONE},
    {"SWAP",       VFM_SWAP,       VFM_FMT_NONE},
    {"ADD",        VFM_ADD,        VFM_FMT_NONE},
    {"SUB",        VFM_SUB,        VFM_FMT_NONE},
    {"MUL",        VFM_MUL,        VFM_FMT_NONE},
    {"DIV",        VFM_DIV,        VFM_FMT_NONE},
    {"AND",        VFM_AND,        VFM_FMT_NONE},
    {"OR",         VFM_OR,         VFM_FMT_NONE},
    {"XOR",        VFM_XOR,        VFM_FMT_NONE},
    {"SHL",        VFM_SHL,        VFM_FMT_NONE},
    {"SHR",        VFM_SHR,        VFM_FMT_NONE},
    {"JMP",        VFM_JMP,        VFM_FMT_OFFSET16},
    {"JEQ",        VFM_JEQ,        VFM_FMT_OFFSET16},
    {"JNE",        VFM_JNE,        VFM_FMT_OFFSET16},
    {"JGT",        VFM_JGT,        VFM_FMT_OFFSET16},
    {"JLT",        VFM_JLT,        VFM_FMT_OFFSET16},
    {"JGE",        VFM_JGE,        VFM_FMT_OFFSET16},
    {"JLE",        VFM_JLE,        VFM_FMT_OFFSET16},
    {"RET",        VFM_RET,        VFM_FMT_NONE},
    {"HASH5",      VFM_HASH5,      VFM_FMT_NONE},
    {"CSUM",       VFM_CSUM,       VFM_FMT_NONE},
    {"PARSE",      VFM_PARSE,      VFM_FMT_NONE},
    {"FLOW_LOAD",  VFM_FLOW_LOAD,  VFM_FMT_NONE},
    {"FLOW_STORE", VFM_FLOW_STORE, VFM_FMT_NONE},
    {"NOT",        VFM_NOT,        VFM_FMT_NONE},
    {"NEG",        VFM_NEG,        VFM_FMT_NONE},
    {"MOD",        VFM_MOD,        VFM_FMT_NONE},
    {NULL, 0, 0}
};

// Error reporting
static void asm_error(assembler_t *asm_state, const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    fprintf(stderr, "Error: %s:%d:%d: ", asm_state->filename, asm_state->line, asm_state->column);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    
    va_end(args);
    asm_state->error_count++;
}

// Read next character from input
static int read_char(assembler_t *asm_state) {
    int c = fgetc(asm_state->input);
    if (c == '\n') {
        asm_state->line++;
        asm_state->column = 1;
    } else {
        asm_state->column++;
    }
    return c;
}

// Peek at next character without consuming it
static int peek_char(assembler_t *asm_state) {
    int c = fgetc(asm_state->input);
    if (c != EOF) {
        ungetc(c, asm_state->input);
    }
    return c;
}

// Skip whitespace (except newlines)
static void skip_whitespace(assembler_t *asm_state) {
    int c;
    while ((c = peek_char(asm_state)) != EOF && isspace(c) && c != '\n') {
        read_char(asm_state);
    }
}

// Read next token from input
static void next_token(assembler_t *asm_state) {
    skip_whitespace(asm_state);
    
    int c = peek_char(asm_state);
    
    // End of file
    if (c == EOF) {
        asm_state->current_token.type = TOKEN_EOF;
        return;
    }
    
    // Newline
    if (c == '\n') {
        read_char(asm_state);
        asm_state->current_token.type = TOKEN_NEWLINE;
        return;
    }
    
    // Comment
    if (c == ';') {
        read_char(asm_state);
        int pos = 0;
        while ((c = peek_char(asm_state)) != EOF && c != '\n' && pos < MAX_TOKEN_LENGTH - 1) {
            asm_state->current_token.text[pos++] = read_char(asm_state);
        }
        asm_state->current_token.text[pos] = '\0';
        asm_state->current_token.type = TOKEN_COMMENT;
        return;
    }
    
    // Number (hex or decimal)
    if (isdigit(c) || c == '-') {
        int pos = 0;
        while ((c = peek_char(asm_state)) != EOF && 
               (isdigit(c) || c == 'x' || c == 'X' || 
                (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') || c == '-') &&
               pos < MAX_TOKEN_LENGTH - 1) {
            asm_state->current_token.text[pos++] = read_char(asm_state);
        }
        asm_state->current_token.text[pos] = '\0';
        asm_state->current_token.type = TOKEN_NUMBER;
        return;
    }
    
    // Identifier or label
    if (isalpha(c) || c == '_') {
        int pos = 0;
        while ((c = peek_char(asm_state)) != EOF && 
               (isalnum(c) || c == '_') && pos < MAX_TOKEN_LENGTH - 1) {
            asm_state->current_token.text[pos++] = read_char(asm_state);
        }
        asm_state->current_token.text[pos] = '\0';
        
        // Check if it's a label (followed by colon)
        if (peek_char(asm_state) == ':') {
            read_char(asm_state);  // consume the colon
            asm_state->current_token.type = TOKEN_LABEL;
        } else {
            asm_state->current_token.type = TOKEN_IDENTIFIER;
        }
        return;
    }
    
    // Unknown character
    asm_error(asm_state, "Unexpected character '%c'", c);
    read_char(asm_state);  // consume the bad character
    next_token(asm_state);  // try again
}

// Get current token (read if not already read)
static token_t *get_token(assembler_t *asm_state) {
    if (asm_state->token_consumed) {
        next_token(asm_state);
        asm_state->token_consumed = 0;
    }
    return &asm_state->current_token;
}

// Consume current token
static void consume_token(assembler_t *asm_state) {
    asm_state->token_consumed = 1;
}

// Parse number (hex or decimal)
static uint64_t parse_number(assembler_t *asm_state, const char *text) {
    char *endptr;
    uint64_t value;
    
    if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
        value = strtoull(text, &endptr, 16);
    } else {
        value = strtoull(text, &endptr, 10);
    }
    
    if (*endptr != '\0') {
        asm_error(asm_state, "Invalid number format: %s", text);
        return 0;
    }
    
    return value;
}

// Find opcode by name
static const opcode_info_t *find_opcode(const char *name) {
    for (const opcode_info_t *op = opcode_table; op->name; op++) {
        if (strcmp(op->name, name) == 0) {
            return op;
        }
    }
    return NULL;
}

// Add label
static void add_label(assembler_t *asm_state, const char *name, uint32_t address) {
    if (asm_state->label_count >= MAX_LABELS) {
        asm_error(asm_state, "Too many labels");
        return;
    }
    
    // Check for duplicate labels
    for (int i = 0; i < asm_state->label_count; i++) {
        if (strcmp(asm_state->labels[i].name, name) == 0) {
            asm_error(asm_state, "Label '%s' already defined", name);
            return;
        }
    }
    
    label_t *label = &asm_state->labels[asm_state->label_count++];
    strncpy(label->name, name, MAX_TOKEN_LENGTH - 1);
    label->name[MAX_TOKEN_LENGTH - 1] = '\0';
    label->address = address;
    label->line = asm_state->line;
    label->resolved = 1;
}

// Find label by name
static label_t *find_label(assembler_t *asm_state, const char *name) {
    for (int i = 0; i < asm_state->label_count; i++) {
        if (strcmp(asm_state->labels[i].name, name) == 0) {
            return &asm_state->labels[i];
        }
    }
    return NULL;
}

// Add forward reference
static void add_forward_ref(assembler_t *asm_state, const char *name, uint32_t address, int is_relative) {
    if (asm_state->forward_ref_count >= MAX_LABELS) {
        asm_error(asm_state, "Too many forward references");
        return;
    }
    
    forward_ref_t *ref = &asm_state->forward_refs[asm_state->forward_ref_count++];
    strncpy(ref->name, name, MAX_TOKEN_LENGTH - 1);
    ref->name[MAX_TOKEN_LENGTH - 1] = '\0';
    ref->address = address;
    ref->line = asm_state->line;
    ref->is_relative = is_relative;
}

// Emit byte to program
static void emit_byte(assembler_t *asm_state, uint8_t byte) {
    if (asm_state->program_size >= MAX_PROGRAM_SIZE) {
        asm_error(asm_state, "Program too large");
        return;
    }
    asm_state->program[asm_state->program_size++] = byte;
}

// Emit 16-bit value (little endian)
static void emit_u16(assembler_t *asm_state, uint16_t value) {
    emit_byte(asm_state, value & 0xFF);
    emit_byte(asm_state, (value >> 8) & 0xFF);
}

// Emit 32-bit value (little endian)
static void emit_u32(assembler_t *asm_state, uint32_t value) {
    emit_byte(asm_state, value & 0xFF);
    emit_byte(asm_state, (value >> 8) & 0xFF);
    emit_byte(asm_state, (value >> 16) & 0xFF);
    emit_byte(asm_state, (value >> 24) & 0xFF);
}

// Emit 64-bit value (little endian)
static void emit_u64(assembler_t *asm_state, uint64_t value) {
    emit_u32(asm_state, value & 0xFFFFFFFF);
    emit_u32(asm_state, (value >> 32) & 0xFFFFFFFF);
}

// Assemble one instruction
static void assemble_instruction(assembler_t *asm_state, const opcode_info_t *op, token_t *token) {
    emit_byte(asm_state, op->opcode);
    
    switch (op->format) {
        case VFM_FMT_NONE:
            // No operands
            break;
            
        case VFM_FMT_IMM16: {
            // 16-bit immediate
            consume_token(asm_state);
            token = get_token(asm_state);
            if (token->type != TOKEN_NUMBER) {
                asm_error(asm_state, "Expected number for %s instruction", op->name);
                return;
            }
            uint64_t value = parse_number(asm_state, token->text);
            if (value > 0xFFFF) {
                asm_error(asm_state, "Value %llu too large for 16-bit immediate", value);
                return;
            }
            emit_u16(asm_state, (uint16_t)value);
            break;
        }
        
        case VFM_FMT_IMM32: {
            // 32-bit immediate
            consume_token(asm_state);
            token = get_token(asm_state);
            if (token->type != TOKEN_NUMBER) {
                asm_error(asm_state, "Expected number for %s instruction", op->name);
                return;
            }
            uint64_t value = parse_number(asm_state, token->text);
            if (value > 0xFFFFFFFF) {
                asm_error(asm_state, "Value %llu too large for 32-bit immediate", value);
                return;
            }
            emit_u32(asm_state, (uint32_t)value);
            break;
        }
        
        case VFM_FMT_IMM64: {
            // 64-bit immediate
            consume_token(asm_state);
            token = get_token(asm_state);
            if (token->type != TOKEN_NUMBER) {
                asm_error(asm_state, "Expected number for %s instruction", op->name);
                return;
            }
            uint64_t value = parse_number(asm_state, token->text);
            emit_u64(asm_state, value);
            break;
        }
        
        case VFM_FMT_OFFSET16: {
            // 16-bit offset (for jumps)
            consume_token(asm_state);
            token = get_token(asm_state);
            
            if (token->type == TOKEN_NUMBER) {
                // Direct offset
                uint64_t value = parse_number(asm_state, token->text);
                if (value > 0xFFFF) {
                    asm_error(asm_state, "Jump offset %llu too large", value);
                    return;
                }
                emit_u16(asm_state, (uint16_t)value);
            } else if (token->type == TOKEN_IDENTIFIER) {
                // Label reference - add forward reference
                add_forward_ref(asm_state, token->text, asm_state->program_size, 1);
                emit_u16(asm_state, 0);  // Placeholder
            } else {
                asm_error(asm_state, "Expected number or label for %s instruction", op->name);
                return;
            }
            break;
        }
        
        default:
            asm_error(asm_state, "Unknown instruction format");
            return;
    }
}

// Resolve forward references
static void resolve_forward_refs(assembler_t *asm_state) {
    for (int i = 0; i < asm_state->forward_ref_count; i++) {
        forward_ref_t *ref = &asm_state->forward_refs[i];
        label_t *label = find_label(asm_state, ref->name);
        
        if (!label) {
            asm_error(asm_state, "Undefined label '%s'", ref->name);
            continue;
        }
        
        int32_t offset;
        if (ref->is_relative) {
            // Relative jump - offset from current position
            offset = (int32_t)label->address - (int32_t)(ref->address + 2);
        } else {
            // Absolute reference
            offset = (int32_t)label->address;
        }
        
        if (offset < -32768 || offset > 32767) {
            asm_error(asm_state, "Jump offset %d out of range for label '%s'", offset, ref->name);
            continue;
        }
        
        // Patch the offset in the program
        uint16_t offset_u16 = (uint16_t)(int16_t)offset;
        asm_state->program[ref->address] = offset_u16 & 0xFF;
        asm_state->program[ref->address + 1] = (offset_u16 >> 8) & 0xFF;
    }
}

// Main assembly function
static int assemble_file(assembler_t *asm_state) {
    // Initialize first token
    asm_state->token_consumed = 1;
    
    while (1) {
        token_t *token = get_token(asm_state);
        
        if (token->type == TOKEN_EOF) {
            break;
        }
        
        if (token->type == TOKEN_NEWLINE || token->type == TOKEN_COMMENT) {
            consume_token(asm_state);
            continue;
        }
        
        if (token->type == TOKEN_LABEL) {
            // Define label
            add_label(asm_state, token->text, asm_state->program_size);
            consume_token(asm_state);
            continue;
        }
        
        if (token->type == TOKEN_IDENTIFIER) {
            // Look up opcode
            const opcode_info_t *op = find_opcode(token->text);
            if (!op) {
                asm_error(asm_state, "Unknown instruction '%s'", token->text);
                consume_token(asm_state);
                continue;
            }
            
            assemble_instruction(asm_state, op, token);
            consume_token(asm_state);
            continue;
        }
        
        asm_error(asm_state, "Unexpected token");
        consume_token(asm_state);
    }
    
    // Resolve forward references
    resolve_forward_refs(asm_state);
    
    return asm_state->error_count == 0;
}

// Main function
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input.vfm> [-o output.bin]\n", argv[0]);
        return 1;
    }
    
    const char *input_file = argv[1];
    const char *output_file = "output.bin";
    
    // Parse command line arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[i + 1];
            i++;
        }
    }
    
    // Initialize assembler
    assembler_t asm_state = {0};
    asm_state.filename = input_file;
    asm_state.line = 1;
    asm_state.column = 1;
    asm_state.token_consumed = 1;
    
    // Open input file
    asm_state.input = fopen(input_file, "r");
    if (!asm_state.input) {
        fprintf(stderr, "Error: Cannot open input file '%s': %s\n", input_file, strerror(errno));
        return 1;
    }
    
    // Assemble the file
    printf("Assembling %s...\n", input_file);
    int success = assemble_file(&asm_state);
    
    fclose(asm_state.input);
    
    if (!success) {
        printf("Assembly failed with %d errors.\n", asm_state.error_count);
        return 1;
    }
    
    // Write output file
    FILE *output = fopen(output_file, "wb");
    if (!output) {
        fprintf(stderr, "Error: Cannot create output file '%s': %s\n", output_file, strerror(errno));
        return 1;
    }
    
    fwrite(asm_state.program, 1, asm_state.program_size, output);
    fclose(output);
    
    printf("Assembly successful: %u bytes written to %s\n", asm_state.program_size, output_file);
    printf("Labels defined: %d\n", asm_state.label_count);
    
    return 0;
}