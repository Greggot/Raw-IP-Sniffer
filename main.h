#pragma once
#include <cstdio>
#include <cstdint>

enum Protocol
{
	_TCP = 0x06,
	_UDP = 0x11,
};

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