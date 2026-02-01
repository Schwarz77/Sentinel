#pragma once
#include "Headers.hpp"
#include "MirrorLogger.hpp"
#include <iostream>


struct LogEvent
{
    uint64_t timestamp;
    uint32_t src_ip;
    uint16_t port;
};

class SentinelEngine 
{
    MirrorLogger& logger;

public:
    SentinelEngine(MirrorLogger& l) 
        : logger(l) 
    {}

    void analyze(const IpHeader* ip, const TcpHeader* tcp) 
    {
        // Simple Fingerprinting by TTL and Window Size
        // Windows: TTL 128, Win 64240 or 8192
        // Linux: TTL 64, Win 29200
        
        bool suspect = false;
        std::string os_guess = "Unknown";

        if (ip->ttl == 128 && tcp->window_size == 8192) 
        {
            os_guess = "Windows (Modern)";
        } 
        else if (ip->ttl == 64 && tcp->window_size == 29200) 
        {
            os_guess = "Linux (Standard)";
        } 
        else if (ip->ttl < 64) 
        {
            // If the TTL is too low, the packet may have passed through too many nodes
            // or it may be a scanning attempt (Nmap)
            suspect = true;
            os_guess = "Nmap/Scapy Scanner?";
        }

        if (suspect || (tcp->flags & 0x02))  // if SYN or suspect
        { 
            log_event(ip, tcp, os_guess);
        }
    }

private:
    void log_event(const IpHeader* ip, const TcpHeader* tcp, const std::string& os) 
    {

        LogEvent event;
        event.timestamp = 123456789;
        event.src_ip = ip->src_ip;
        event.port = tcp->src_port;

        logger.write_binary(event); 
        
        std::cout << "[SENTINEL] Detected " << os << " from IP: " 
                  << (ip->src_ip & 0xFF) << "." << ((ip->src_ip >> 8) & 0xFF) << "." << ((ip->src_ip >> 16) & 0xFF) << "." << ((ip->src_ip >> 24) & 0xFF) << std::endl;

    }
};