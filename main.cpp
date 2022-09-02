#include "main.h"

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
    unsigned char buff[0xFFF]{ 0 };

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        ReportAndExit("WSA startup");

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock < 0)
        ReportAndExit("Socket creation");

    sockaddr_in listen;
    listen.sin_family = AF_INET;
    stringToIP(argv[IPaddr], listen);
    listen.sin_port = htons(0);

    if (bind(sock, (sockaddr*)&listen, sizeof(listen)) < 0)
        ReportAndExit("Bind");

    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval)) < 0)
        ReportAndExit("IPPROTO_IP set error");
    int in;
    if (WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), 0, 0, (LPDWORD)&in, 0, 0) < 0)
        ReportAndExit("SIO_RCVALL set error");

    char from[INET_ADDRSTRLEN]{ 0 };
    char to[INET_ADDRSTRLEN]{ 0 };

    sockaddr_in someone;
    int someonesize = sizeof(someone);
    int length = 0;
    while (true)
    {
        length = recvfrom(sock, (char*)buff, sizeof(buff), 0, (sockaddr*)&someone, &someonesize);
        if (length < 0)
        {
            closesocket(sock);
            WSACleanup();
            ReportAndExit("recvfrom");
        }

        IP::Header header;
        memcpy(&header, buff, sizeof(header));

        inet_ntop(AF_INET, &(header.source), from, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(header.destination), to, INET_ADDRSTRLEN);


        printf("Version(%u) IHL(%u), DSCP(%u) ECN(%u), \n\
            length(%u), identification(%u), flags(%u), \n\
            offset(%u), ttl(%u), protocol(%u) \n\
            %s -> %s, raw:\n",
            header.version_ihl.Version, header.version_ihl.IHL,
            header.dscp_ecn.DSCP, header.dscp_ecn.ECN,
            header.length, header.identification,
            header.flags_offset.flags, header.flags_offset.offset,
            header.ttl, header.protocol,
            from, to);

        for (int i = 0; i < length; ++i)
            printf("%02X ", buff[i]);
        printf("\n");

    }

    closesocket(sock);
    WSACleanup();
    return 1;
}