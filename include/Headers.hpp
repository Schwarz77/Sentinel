#pragma once
#include <cstdint>

#pragma pack(push, 1)

// L2: Ethernet Header
struct EthHeader 
{
    uint8_t  dst_mac[6];
    uint8_t  src_mac[6];
    uint16_t eth_type; // 0x0800 - IPv4
};

// L3: IPv4 Header
struct IpHeader 
{
    uint8_t  version_ihl;   // version (4 bit) + header len (4 bit)
    uint8_t  tos;           // Type of Service
    uint16_t total_len;     // full packet len
    uint16_t id;            // id fragment
    uint16_t fragment_offset;
    uint8_t  ttl;           // Time to Live
    uint8_t  protocol;      // 6 - TCP, 17 - UDP
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;

    uint8_t header_len() const { return (version_ihl & 0x0F) * 4; }
};

// L4: TCP Header
struct TcpHeader 
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset; 
    uint8_t  flags;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_ptr;

    // TCP flags
    bool is_syn() const { return flags & 0x02; }
    bool is_ack() const { return flags & 0x10; }

    uint8_t header_len() const { return (data_offset >> 4) * 4; }
    

    void parse_options(const uint8_t* packet_end) const 
	{
        const uint8_t* opt_ptr = reinterpret_cast<const uint8_t*>(this) + 20;
        const uint8_t* end_ptr = reinterpret_cast<const uint8_t*>(this) + header_len();

        while (opt_ptr < end_ptr && opt_ptr < packet_end) 
		{
            uint8_t opt_type = *opt_ptr;
            if (opt_type == 0) 
				break;
            if (opt_type == 1) 
			{ opt_ptr++; continue; }
            
            uint8_t opt_len = *(opt_ptr + 1);
            if (opt_type == 2) 
			{
                uint16_t mss = (opt_ptr[2] << 8) | opt_ptr[3];
                // save mss for analyse
            }
            opt_ptr += opt_len;
        }
    }
};
#pragma pack(pop)