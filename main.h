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
	union VersionIHL
	{
		uint8_t raw;
		struct
		{
			uint8_t IHL : 4;
			uint8_t Version : 4;
		};
	};

	union DSCP_ECN
	{
		uint8_t raw;
		struct
		{
			uint8_t ECN : 2;
			uint8_t DSCP : 6;
		};
	};

	union FlagsOffset
	{
		uint16_t raw;
		struct
		{
			uint16_t flags : 3;
			uint16_t offset : 13;
		};
	};

	struct Header
	{
		VersionIHL version_ihl;
		DSCP_ECN dscp_ecn;
		uint16_t length;
		uint16_t identification;
		FlagsOffset flags_offset;
		uint8_t ttl;
		uint8_t protocol;
		uint16_t checksum;
		uint32_t source;
		uint32_t destination;
	};
}