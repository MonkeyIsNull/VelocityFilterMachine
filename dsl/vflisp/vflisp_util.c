#include "vflisp_types.h"
#include "../../../PacketVelocity/include/pcv_flow.h"
#include <string.h>
#include <arpa/inet.h>

// Helper function to parse IPv6 extension headers for field extraction
static int parse_ipv6_ext_for_field(const uint8_t *packet, uint16_t len, pcv_ipv6_ext_headers *ext_info) {
    // Simple IPv6 extension header parsing for field extraction
    memset(ext_info, 0, sizeof(pcv_ipv6_ext_headers));
    
    if (len < 54) return -1;  // Not enough data for IPv6
    
    const uint8_t *ip_header = packet + 14;  // Skip Ethernet
    uint8_t version = (ip_header[0] >> 4) & 0x0F;
    if (version != 6) return -1;  // Not IPv6
    
    uint8_t next_header = ip_header[6];
    uint16_t offset = 40;  // IPv6 header is 40 bytes
    
    ext_info->final_protocol = next_header;
    
    // Parse extension headers
    while (offset < (len - 14)) {
        // Check if this is an extension header
        bool is_ext_header = false;
        switch (next_header) {
            case 0:   // Hop-by-Hop Options
            case 43:  // Routing Header
            case 44:  // Fragment Header
            case 51:  // Authentication Header
            case 60:  // Destination Options
            case 135: // Mobility Header
                is_ext_header = true;
                break;
            default:
                is_ext_header = false;
                break;
        }
        
        if (!is_ext_header) break;
        
        if ((14 + offset + 2) > len) break;  // Not enough data
        
        const uint8_t *ext_header = ip_header + offset;
        uint16_t ext_len = 0;
        
        // Calculate extension header length
        switch (next_header) {
            case 0:   // Hop-by-Hop Options
            case 60:  // Destination Options
            case 43:  // Routing Header
                ext_len = (ext_header[1] + 1) * 8;
                break;
            case 44:  // Fragment Header
                ext_len = 8;
                // Extract fragment information
                if (ext_len >= 8) {
                    uint16_t frag_info = ntohs(*(uint16_t*)(ext_header + 2));
                    ext_info->fragment_offset = (frag_info >> 3) & 0x1FFF;
                    ext_info->fragment_flags = frag_info & 0x0007;
                    ext_info->fragment_id = ntohl(*(uint32_t*)(ext_header + 4));
                }
                break;
            case 51:  // Authentication Header
                ext_len = (ext_header[1] + 2) * 4;
                break;
            case 135: // Mobility Header
                ext_len = ext_header[1] + 8;
                break;
        }
        
        if (ext_len == 0 || (offset + ext_len) > (len - 14)) break;
        
        ext_info->has_ext_headers = 1;
        ext_info->ext_header_count++;
        ext_info->total_ext_length += ext_len;
        
        next_header = ext_header[0];
        offset += ext_len;
        ext_info->final_protocol = next_header;
    }
    
    return 0;
}

// Get field offset with dynamic calculation support
uint16_t vfl_get_field_offset(vfl_field_type_t field_type, const uint8_t *packet, uint16_t len) {
    if (!packet || len == 0) return 0;
    
    const vfl_field_info_t *info = &vfl_field_info[field_type];
    
    // For fields with fixed offsets, return immediately
    if (info->offset != 0) {
        return info->offset;
    }
    
    // Dynamic offset calculation for IPv6 fields
    switch (field_type) {
        case VFL_FIELD_SRC_IP6:
            // IPv6 source address is at offset 22 (14 Ethernet + 8 into IPv6 header)
            return 22;
            
        case VFL_FIELD_DST_IP6:
            // IPv6 destination address is at offset 38 (14 Ethernet + 24 into IPv6 header)
            return 38;
            
        // Transport layer fields that need dynamic offset calculation for IPv6
        case VFL_FIELD_SRC_PORT:
        case VFL_FIELD_DST_PORT: {
            // Check IP version first
            if (len < 15) return 0;
            uint8_t version = (packet[14] >> 4) & 0x0F;
            
            if (version == 4) {
                // IPv4 has fixed offsets
                return (field_type == VFL_FIELD_SRC_PORT) ? 34 : 36;
            } else if (version == 6) {
                // IPv6 requires extension header parsing
                pcv_ipv6_ext_headers ext_info;
                if (parse_ipv6_ext_for_field(packet, len, &ext_info) != 0) {
                    return 0;  // Parse failed
                }
                
                // Transport header starts after IPv6 header (40 bytes) + extension headers
                uint16_t transport_offset = 14 + 40 + ext_info.total_ext_length;
                
                // Check if we have enough packet data for transport header
                if (transport_offset + 4 > len) return 0;
                
                // Source port is at offset 0, destination port at offset 2 in transport header
                return transport_offset + ((field_type == VFL_FIELD_SRC_PORT) ? 0 : 2);
            }
            return 0;
        }
        
        // IPv6 extension header fields require parsing
        case VFL_FIELD_HAS_EXT_HDR:
        case VFL_FIELD_EXT_HDR_COUNT:
        case VFL_FIELD_EXT_HDR_LEN:
        case VFL_FIELD_FINAL_PROTO:
        case VFL_FIELD_FRAG_ID:
        case VFL_FIELD_FRAG_OFFSET:
        case VFL_FIELD_FRAG_FLAGS:
            // These fields don't have packet offsets - they're computed values
            // Return 0 to indicate special handling is needed
            return 0;
            
        default:
            return info->offset;
    }
}

// Check if a field supports the given IP version
bool vfl_field_supports_ip_version(vfl_field_type_t field_type, uint8_t ip_version) {
    if (field_type >= VFL_FIELD_MAX) return false;
    
    const vfl_field_info_t *info = &vfl_field_info[field_type];
    
    switch (info->addr_family) {
        case VFL_ADDR_ANY:
            return true;
        case VFL_ADDR_IPV4:
            return (ip_version == 4);
        case VFL_ADDR_IPV6:
            return (ip_version == 6);
        default:
            return false;
    }
}

// Extract IPv6 extension header field values
uint64_t vfl_extract_ipv6_ext_field(vfl_field_type_t field_type, const uint8_t *packet, uint16_t len) {
    pcv_ipv6_ext_headers ext_info;
    
    if (parse_ipv6_ext_for_field(packet, len, &ext_info) != 0) {
        return 0;  // Parse failed
    }
    
    switch (field_type) {
        case VFL_FIELD_HAS_EXT_HDR:
            return ext_info.has_ext_headers;
            
        case VFL_FIELD_EXT_HDR_COUNT:
            return ext_info.ext_header_count;
            
        case VFL_FIELD_EXT_HDR_LEN:
            return ext_info.total_ext_length;
            
        case VFL_FIELD_FINAL_PROTO:
            return ext_info.final_protocol;
            
        case VFL_FIELD_FRAG_ID:
            return ext_info.fragment_id;
            
        case VFL_FIELD_FRAG_OFFSET:
            return ext_info.fragment_offset;
            
        case VFL_FIELD_FRAG_FLAGS:
            return ext_info.fragment_flags;
            
        // Transport layer fields with dynamic offset calculation
        case VFL_FIELD_SRC_PORT:
        case VFL_FIELD_DST_PORT: {
            // First, determine IP version without calling parse_ipv6_ext_for_field to avoid recursion
            if (len < 15) return 0;
            uint8_t version = (packet[14] >> 4) & 0x0F;
            
            if (version == 4) {
                // IPv4 - use fixed offsets directly
                uint16_t offset = (field_type == VFL_FIELD_SRC_PORT) ? 34 : 36;
                if (offset + 2 > len) return 0;
                uint16_t port = ntohs(*(uint16_t*)(packet + offset));
                return port;
            } else if (version == 6) {
                // IPv6 - parse extension headers to find transport layer
                uint16_t offset = vfl_get_field_offset(field_type, packet, len);
                if (offset == 0 || offset + 2 > len) {
                    return 0;  // Invalid offset or not enough data
                }
                
                // Read 16-bit port value in network byte order
                uint16_t port = ntohs(*(uint16_t*)(packet + offset));
                return port;
            }
            
            return 0;  // Unknown IP version
        }
            
        default:
            return 0;
    }
}