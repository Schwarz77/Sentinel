#include "IPacketSource.hpp"
#include <windows.h>
#include "windivert.h"
#include <iostream>
#include <string>


class WinDivertSource : public IPacketSource 
{
public:
    WinDivertSource() 
    {
    }

    ~WinDivertSource()
    {
        close();
    }

    WinDivertSource(const WinDivertSource&) = delete;
    WinDivertSource& operator=(const WinDivertSource&) = delete;

private:
    HANDLE m_handle = INVALID_HANDLE_VALUE;
    uint8_t m_buffer[65535]; // buffer for one packet

public:
    bool open(const char* filter) override 
    {
        //m_handle = WinDivertOpen(filter, WINDIVERT_LAYER_DATALINK, 0, 0);    // WINDIVERT_LAYER_DATALINK - (L2) 
        m_handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);   // WINDIVERT_LAYER_NETWORK — L3 (IP)

        if (m_handle == INVALID_HANDLE_VALUE) 
        {
            DWORD err = GetLastError();
            std::string reason;

            switch (err) {
            case ERROR_ACCESS_DENIED:
                reason = "Access Denied (Did you run as Administrator?)";
                break;
            case ERROR_FILE_NOT_FOUND:
                reason = "WinDivert64.sys not found in the executable directory.";
                break;
            case ERROR_INVALID_PARAMETER:
                reason = "Invalid filter syntax.";
                break;
            case ERROR_INVALID_IMAGE_HASH: //577
                reason = "Driver signature verification failed (Check Secure Boot).";
                break;
            default:
                reason = "Unknown error code: " + std::to_string(err);
            }

            throw std::runtime_error("Sentinel Critical Error: " + reason);
        }
        return true;
    }

    bool receive(RawPacket& pkt) override 
    { 
        WINDIVERT_ADDRESS addr;
        UINT recvLen;

        if (!WinDivertRecv(m_handle, m_buffer, sizeof(m_buffer), &recvLen, &addr)) 
        {
            DWORD err = GetLastError();
            if (err != ERROR_INSUFFICIENT_BUFFER) 
            {
                int ddd = 0;
            }

            return false;
        }

        pkt.data = m_buffer;
        pkt.length = recvLen;
        
        // in WinDivert address need to subsequent sending
        lastAddr = addr; 
        return true;
    }

    void send(RawPacket& pkt) override 
    {
        WinDivertSend(m_handle, pkt.data, pkt.length, NULL, &lastAddr);
    }

    void close() override {
        if (m_handle != INVALID_HANDLE_VALUE) 
        {
            WinDivertClose(m_handle);
        }
    }

private:
    WINDIVERT_ADDRESS lastAddr; // for now
};