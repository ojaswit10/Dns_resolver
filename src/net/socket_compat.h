#pragma once

// Smooths over the differences between Winsock and POSIX sockets so the rest
// of the code can use one API. Include this instead of the platform headers.

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
// <windows.h> defines IN and OUT as empty macros, which break RecordClass::IN.
#undef IN
#undef OUT
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace dns::net {

#ifdef _WIN32
using SocketHandle = SOCKET;
using SockLen = int;
constexpr SocketHandle kInvalidSocket = INVALID_SOCKET;
#else
using SocketHandle = int;
using SockLen = socklen_t;
constexpr SocketHandle kInvalidSocket = -1;
#endif

// Must run before the first socket call. Safe to call many times.
bool init_sockets();

void close_socket(SocketHandle socket);

// Waits until `socket` is readable. Returns false on timeout or error.
bool wait_readable(SocketHandle socket, int timeout_ms);

// Connects `socket` to `server`, giving up after `timeout_ms`. Returns false on timeout or error.
bool connect_with_timeout(SocketHandle socket, const sockaddr_in& server, int timeout_ms);

}  // namespace dns::net
