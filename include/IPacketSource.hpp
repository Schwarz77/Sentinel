#pragma once
#include <cstdint>
#include <vector>

struct RawPacket {
    uint8_t* data;
    uint32_t length;
};

class IPacketSource {
public:
    virtual ~IPacketSource() = default;
    virtual bool open(const char* filter) = 0;
    virtual bool receive(RawPacket& pkt) = 0;
    virtual void send(RawPacket& pkt) = 0;
    virtual void close() = 0;
};