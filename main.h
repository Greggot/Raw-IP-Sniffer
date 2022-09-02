#pragma once
#include <stdio.h>
#include <winsock2.h>
#include <mstcpip.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable : 4996)

#include <cstdio>
#include <cstdint>

#define ReportErrorAndExit() { error = WSAGetLastError(); return; }

inline void stringToIP(char* string, sockaddr_in& sockaddr)
{
	sockaddr.sin_addr.s_addr = 0;
	for (uint8_t i = 0; i < sizeof(sockaddr.sin_addr.s_addr); ++i, ++string)
	{
		sockaddr.sin_addr.s_addr >>= 8;
		sockaddr.sin_addr.s_addr |= strtoul(string, &string, 10) << 24;
	}
}

namespace IP
{
	static const uint8_t minIHL = 5;
	struct Header
	{
		union
		{
			uint8_t VersionIHL;
			struct
			{
				uint8_t IHL		: 4;
				uint8_t Version : 4;
			};
		};
		union
		{
			uint8_t DSCP_ECN;
			struct
			{
				uint8_t ECN  : 2;
				uint8_t DSCP : 6;
			};
		};
		uint16_t length;
		uint16_t identification;
		union
		{
			uint16_t FlagsOffset;
			struct
			{
				uint16_t flags  : 3;
				uint16_t offset : 13;
			};
		};
		uint8_t ttl;
		uint8_t protocol;
		uint16_t checksum;
		uint32_t source;
		uint32_t destination;
	};
}

namespace TCP
{

	struct Header
	{
		uint16_t source;
		uint16_t destination;
		uint32_t sequenceNumber;
		uint32_t acknowledgmentNumber;
		union
		{
			uint8_t offsetNS;
			struct
			{
				uint8_t reserved : 3;
				uint8_t NS : 1;
				uint8_t offset : 4;
			};
		};
		union
		{
			uint8_t flags;
			struct
			{
				uint8_t CWR : 1;
				uint8_t ECE : 1;
				uint8_t URG : 1;
				uint8_t ACK : 1;
				uint8_t PSH : 1;
				uint8_t RST : 1;
				uint8_t SYN : 1;
				uint8_t FIN : 1;
			};
		};
		uint16_t windowSize;
		uint16_t checksum;
		uint16_t urgentPointer;
	};
}

namespace UDP
{
	struct Header
	{
		uint16_t source;
		uint16_t destination;
		uint16_t length;
		uint16_t checksum;
	};
}