#include "main.h"
#include "RawSocket.hpp"
#pragma warning(disable : 4996)

template<class type>
static inline void ReadHeaderFixPorts(type& header, const void* data)
{
    memcpy(&header, data, sizeof(header));
    header.source = htons(header.source);
    header.destination = htons(header.destination);
}

enum Argument
{
    IPaddr = 1,
    File,

    Amount,
};

#define Kilobyte 1024
constexpr int Megabyte() { return Kilobyte * Kilobyte; }

int main(int argc, char* argv[])
{
    if (argc < Amount)
    {
        printf("Usage: RawSocket.exe <ip> <log_path>");
        return 0;
    }

    FILE* log = fopen(argv[File], "a");
    if (log == nullptr)
    {
        printf("Failed to open log...\n");
        return 0;
    }

    std::thread progress = std::thread([log]() {
        float size = 0;
        
        while (log)
        {
            size = ftell(log);
            printf("\rLog size:");
            if (size > Megabyte())
                printf("%.2f MB", size / Megabyte());
            else
                printf("%.2f KB", size / Kilobyte);
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });

    auto ip = [&log](const IP::Header& header) {
        char from[INET_ADDRSTRLEN]{ 0 };
        char to[INET_ADDRSTRLEN]{ 0 };

        inet_ntop(AF_INET, &(header.source), from, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(header.destination), to, INET_ADDRSTRLEN);

        fprintf(log, "%s -> %s: ver(%u) IHL(%u), DSCP(%u) ECN(%u), length(%u), id(%u), flags(%u), offset(%u), ttl(%u), protocol(%u)\n",
            from, to,
            header.Version, header.IHL,
            header.DSCP, header.ECN,
            header.length, header.identification,
            header.flags, header.offset,
            header.ttl, header.protocol);
    };

    auto udp = [&log](const void* data, const size_t size) {
        UDP::Header header;
        ReadHeaderFixPorts(header, data);
        header.length = htons(header.length);

        fprintf(log, "UDP: %u -> %u, length(%u), checksum(%04X)\n\n", header.source, header.destination, header.length, header.checksum);
    };

    auto tcp = [&log](const void* data, const size_t size) {
        TCP::Header header;
        ReadHeaderFixPorts(header, data);

        fprintf(log, "TCP: %u -> %u, SN(%u), ACKN(%u), offset(%u), flags(%u%u%u%u%u%u%u%u%u), WinSize(%u), Checksum(%04X), URGptr(%04X)\n\n",
            header.source, header.destination,
            header.sequenceNumber, header.acknowledgmentNumber,
            header.offset, header.NS, header.CWR, header.ECE,
            header.URG, header.ACK, header.PSH, header.RST,
            header.SYN, header.FIN, header.windowSize,
            header.checksum, header.urgentPointer);
    };

    
    RawSocket sniffer(argv[IPaddr], 0xFFFF);

    sniffer.set(ip);
    sniffer.set(_UDP, udp);
    sniffer.set(_TCP, tcp);

    sniffer.StartSniffing();
    progress.join();
    
    return 0;
}