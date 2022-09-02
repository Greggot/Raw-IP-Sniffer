#include "RawSocket.hpp"

RawSocket::RawSocket(char ip[], size_t size)
	: size(size), Buffer(new uint8_t[size]{0})
{
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        ReportErrorAndExit();

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock < 0)
        ReportErrorAndExit();

    sockaddr_in listen;
    listen.sin_family = AF_INET;
    stringToIP(ip, listen);
    listen.sin_port = htons(0);

    if (bind(sock, (sockaddr*)&listen, sizeof(listen)) < 0)
        ReportErrorAndExit();

    int optval = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, (char*)&optval, sizeof(optval)) < 0)
        ReportErrorAndExit();
    int in;
    if (WSAIoctl(sock, SIO_RCVALL, &optval, sizeof(optval), 0, 0, (LPDWORD)&in, 0, 0) < 0)
        ReportErrorAndExit();
}

void RawSocket::StartSniffing()
{
    isRunning = true;

    std::thread([this]() {
        int length;
        sockaddr_in someone;
        int someonesize = sizeof(someone);


        while (isRunning)
        {
            IP::Header header;
            length = recvfrom(sock, (char*)Buffer, size, 0, (sockaddr*)&someone, &someonesize);
            if (length < sizeof(header))
                ReportErrorAndExit();

            memcpy(&header, Buffer, sizeof(header));
            header.length = htons(header.length);
            if (IPhandler)
                IPhandler(header);

            uint8_t* nextheaderptr = Buffer + sizeof(header) + ((header.IHL - IP::minIHL) * sizeof(uint32_t));

            auto res = callbacks.find(header.protocol);
            if (res != callbacks.end())
                res->second(nextheaderptr, length - (nextheaderptr - Buffer));

            memset(Buffer, 0, length);
        }
    }).join();
    
    StopSniffing();
}

void RawSocket::StopSniffing()
{
    isRunning = false;
    closesocket(sock);
    WSACleanup();
}
