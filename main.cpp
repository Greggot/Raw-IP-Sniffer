#include "main.h"
#include "RawSocket.hpp"

static inline void ReportAndExit(const char description[])
{
    printf("%s %i\n", description, WSAGetLastError());
    exit(1);
}

enum Argument
{
    IPaddr = 1,
    File,

    Amount,
};

int main(int argc, char* argv[])
{
    auto ip = [](const IP::Header& header) {
        char from[INET_ADDRSTRLEN]{ 0 };
        char to[INET_ADDRSTRLEN]{ 0 };

        inet_ntop(AF_INET, &(header.source), from, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(header.destination), to, INET_ADDRSTRLEN);

        printf("Version(%u) IHL(%u), DSCP(%u) ECN(%u), \n\
            length(%u), id(%u), flags(%u), \n\
            offset(%u), ttl(%u), protocol(%u) \n\
            %s -> %s, raw:\n",
            header.Version, header.IHL,
            header.DSCP, header.ECN,
            header.length, header.identification,
            header.flags, header.offset,
            header.ttl, header.protocol,
            from, to);
    };

    auto udp = [](const void* data, const size_t size) {
        UDP::Header header;

        memcpy(&header, data, sizeof(header));
        header.source = htons(header.source);
        header.destination = htons(header.destination);
        header.length = htons(header.length);

        printf("UDP package: %u -> %u, length(%u), checksum(%04X)\n", header.source, header.destination, header.length, header.checksum);
    };

    auto tcp = [](const void* data, const size_t size) {
        TCP::Header header;

        memcpy(&header, data, sizeof(header));
        header.source = htons(header.source);
        header.destination = htons(header.destination);
        printf("TCP package: %u -> %u: ", header.source, header.destination);

        printf("SN(%u), ACKN(%u), offset(%u), reserved(%u)\n\
                flags(%u %u %u %u %u %u %u %u %u), WinSize(%u),\n\
                Checksum(%04X), URGptr(%04X) \n",
            header.sequenceNumber, header.acknowledgmentNumber,
            header.offset, header.reserved, header.NS, header.CWR, header.ECE,
            header.URG, header.ACK, header.PSH, header.RST,
            header.SYN, header.FIN, header.windowSize,
            header.checksum, header.urgentPointer);
    };

    
    RawSocket sniffer(argv[IPaddr], 0xFFFF);

    sniffer.set(ip);
    sniffer.set(_UDP, udp);
    sniffer.set(_TCP, tcp);

    sniffer.StartSniffing();
    
    return 0;
}