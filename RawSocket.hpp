#pragma once
#include <winsock2.h>
#include <mstcpip.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

#include <functional>
#include <map>
#include <thread>


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
				uint8_t IHL : 4;
				uint8_t Version : 4;
			};
		};
		union
		{
			uint8_t DSCP_ECN;
			struct
			{
				uint8_t ECN : 2;
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
				uint16_t flags : 3;
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

typedef std::function<void(const void*, const size_t)> callback;
typedef std::function<void(const IP::Header&)> IPheadHandler;

#define ReportErrorAndExit() { error = WSAGetLastError(); return; }
class RawSocket
{
private:
	std::map<uint8_t, callback> callbacks;
	IPheadHandler IPhandler = nullptr;

	uint8_t* Buffer = nullptr;
	const size_t size;
	int error;
	SOCKET sock;

	bool isRunning = false;
public:
	RawSocket(char ip[], size_t size);

	void StartSniffing();
	void set(uint8_t protocol, callback handler) { callbacks.insert({protocol, handler}); }
	void set(IPheadHandler handler) { IPhandler = handler; }

	void StopSniffing();
	int getError() const { return error; }
};