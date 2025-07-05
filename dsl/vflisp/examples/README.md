# VFLisp Examples

This directory contains example VFLisp programs that demonstrate various features of the language.

## Files

1. **tcp_filter.vfl** - Basic TCP protocol filter
   - Accepts only TCP packets (protocol 6)
   - Demonstrates simple equality comparison

2. **web_filter.vfl** - Web traffic filter
   - Accepts HTTP (port 80) and HTTPS (port 443) traffic
   - Demonstrates logical AND and OR operations

3. **port_range.vfl** - Port range filter
   - Accepts packets with destination ports between 1000-2000
   - Demonstrates arithmetic comparisons (>= and <=)

4. **ip_filter.vfl** - IP address range filter
   - Accepts packets from private IP ranges (192.168.1.0/24 and 10.0.0.0/8)
   - Demonstrates 32-bit IP address comparisons

5. **tcp_syn_filter.vfl** - TCP SYN packet filter
   - Accepts only TCP SYN packets
   - Demonstrates bitwise operations on TCP flags

6. **complex_filter.vfl** - Complex conditional filter
   - Demonstrates nested if statements and complex logic
   - Accepts SSH from trusted networks or any HTTPS traffic

7. **arithmetic_demo.vfl** - Arithmetic operations
   - Accepts packets where destination port is divisible by 10
   - Demonstrates modulo operation

## Running Examples

To compile and test these examples:

```bash
# Compile an example
./vflispc examples/tcp_filter.vfl -o tcp_filter.bin

# Show AST for an example
./vflispc -a examples/web_filter.vfl

# Test an example with a sample packet
./vflispc -t examples/tcp_syn_filter.vfl

# Compile and disassemble
./vflispc -d examples/complex_filter.vfl
```

## Syntax Reference

### Data Types
- **Integers**: 64-bit signed integers (e.g., `42`, `-100`)
- **Packet fields**: Access packet data (e.g., `proto`, `src-ip`, `dst-port`)

### Operators
- **Arithmetic**: `+`, `-`, `*`, `/`, `%`
- **Comparison**: `=`, `!=`, `>`, `>=`, `<`, `<=`
- **Logical**: `and`, `or`, `not`
- **Bitwise**: `&`, `|`, `^`, `<<`, `>>`

### Control Flow
- **if**: `(if condition then-expr else-expr)`

### Packet Fields
- `proto`: IP protocol (8-bit, offset 23)
- `src-ip`: Source IP address (32-bit, offset 26)
- `dst-ip`: Destination IP address (32-bit, offset 30)
- `src-port`: Source port (16-bit, offset 34)
- `dst-port`: Destination port (16-bit, offset 36)
- `ethertype`: Ethernet type (16-bit, offset 12)
- `ip-len`: IP packet length (16-bit, offset 16)
- `tcp-flags`: TCP flags (8-bit, offset 47)

### Common Patterns

#### Protocol Filtering
```lisp
(= proto 6)          ; TCP
(= proto 17)         ; UDP
(= proto 1)          ; ICMP
```

#### Port Filtering
```lisp
(= dst-port 80)      ; HTTP
(= dst-port 443)     ; HTTPS
(= dst-port 22)      ; SSH
```

#### IP Address Ranges
```lisp
; 192.168.1.0/24 = 3232235776 to 3232236031
(and (>= src-ip 3232235776)
     (<= src-ip 3232236031))
```

#### TCP Flag Checking
```lisp
(= (& tcp-flags 2) 2)    ; SYN flag
(= (& tcp-flags 16) 16)  ; ACK flag
(= (& tcp-flags 1) 1)    ; FIN flag
```

#### Complex Logic
```lisp
(if (= proto 6)
    (or (= dst-port 80)
        (= dst-port 443))
    0)
```