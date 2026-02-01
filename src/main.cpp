#include <iostream>
#include <signal.h>
#include "Headers.hpp"
#include "IPacketSource.hpp"
#include "SentinelEngine.hpp"
#include "WinDivertSource.cpp"



class MockSource : public IPacketSource 
{
public:
    bool open(const char*) override { return true; }
    bool receive(RawPacket&) override { return false; }
    void send(RawPacket&) override {}
    void close() override {}
};



bool g_running = true;
void signal_handler(int) { g_running = false; }



int main()
{
    signal(SIGINT, signal_handler);


#ifdef _WIN32
    std::unique_ptr<IPacketSource> pSource = std::make_unique<WinDivertSource>();
#else
    std::unique_ptr<IPacketSource> pSource = std::make_unique<MockSource>();
#endif

    IPacketSource& source = *pSource.get();

    MirrorLogger logger(128 * 1024 * 1024);

    SentinelEngine engine(logger);

    try
    {

        //std::string filter("true");
        std::string filter("tcp and inbound");  // for SYN-Proxy
        //std::string filter("tcp and (tcp.SrcPort == 80 or tcp.DstPort == 80)");
        //std::string filter("tcp.DstPort == 80 or tcp.DstPort == 443");
        

        if (!pSource->open(filter.data()))
        {
            return 1;
        }

        std::cout << "Sentinel Engine started..." << std::endl;

        while (g_running)
        {
            RawPacket pkt;
            if (source.receive(pkt))
            {
                //std::cout << "Captured packet, Length: " << pkt.length << std::endl;

                //// L2
                //auto eth = reinterpret_cast<EthHeader*>(pkt.data);
                //if (eth->eth_type == 0x0008) 
                //{
                //    auto ip = reinterpret_cast<IpHeader*>(pkt.data + 14);

                //    if (ip->protocol == 6) // TCP
                //    {
                //        auto tcp = reinterpret_cast<TcpHeader*>((uint8_t*)ip + ip->header_len());

                //        //if (tcp->flags & 0x02) // SYN
                //        {  
                //            //std::cout << "SYN from " << std::hex << ip->src_ip
                //            //    << " Window: " << std::dec << tcp->window_size << std::endl;

                //            engine.analyze(ip, tcp);
                //        }
                //    }
                //}
                ////


                // L3
                auto ip = reinterpret_cast<IpHeader*>(pkt.data);

                if ((ip->version_ihl >> 4) == 4)
                {
                    if (ip->protocol == 6) // TCP
                    {
                        auto tcp = reinterpret_cast<TcpHeader*>((uint8_t*)ip + ip->header_len());

                        engine.analyze(ip, tcp);
                    }
                }

                source.send(pkt);
            }
        }

        std::cout << "Sentinel Engine stopped." << std::endl;

    }
    catch (std::runtime_error& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;

    }
    catch (std::exception& ex)
    {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
    catch (...)
    {
        std::cerr << "Unknown Error" << std::endl;
    }


    return 0;
}