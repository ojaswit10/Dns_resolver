#include "net/socket_compat.h"

namespace dns::net {

bool init_sockets() {
#ifdef _WIN32
    static const bool initialized = [] {
        WSADATA data;
        return WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }();
    return initialized;
#else
    return true;
#endif
}

void close_socket(SocketHandle socket) {
#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}

bool wait_readable(SocketHandle socket, int timeout_ms) {
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(socket, &readable);

    timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000;

    // The first argument is ignored on Windows.
    return select(static_cast<int>(socket) + 1, &readable, nullptr, nullptr, &timeout) > 0;
}

}  // namespace dns::net
