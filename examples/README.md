# VFM Example Filters

This directory contains example packet filters written in VFM assembly language.

## Filters

### tcp_filter.vfm
TCP SYN flood detection filter that:
- Checks for IPv4 packets
- Validates TCP protocol
- Identifies SYN-only packets
- Tracks connection attempts per source IP using flow tables
- Drops packets when SYN rate exceeds 100 packets/second

### ddos_detect.vfm
HTTP DDoS detection filter that:
- Filters for IPv4 TCP packets on ports 80/443
- Identifies HTTP GET/POST requests
- Rate limits HTTP requests per source IP
- Drops requests when rate exceeds 50 requests/second

### rate_limit.vfm
General connection rate limiting filter that:
- Monitors TCP SYN packets (new connections)
- Tracks connection attempts per source IP
- Limits to 10 new connections per second per source
- Drops excessive connection attempts

## Usage

These filters are written in VFM assembly language and need to be compiled to bytecode before use with the VFM runtime.

Example usage:
```bash
# Compile filter to bytecode
vfm-asm tcp_filter.vfm -o tcp_filter.bin

# Test filter against packet capture
vfm-test tcp_filter.bin packets.pcap

# Benchmark filter performance
vfm-bench tcp_filter.bin
```

## Packet Structure Reference

- Ethernet header: 14 bytes
- IPv4 header starts at offset 14
- TCP header starts at offset 34 (for IPv4)
- Common offsets:
  - Offset 12: EtherType (0x0800 for IPv4)
  - Offset 23: IP Protocol (6 for TCP)
  - Offset 26: Source IP address
  - Offset 30: Destination IP address
  - Offset 36: TCP destination port
  - Offset 47: TCP flags
  - Offset 54: TCP payload start