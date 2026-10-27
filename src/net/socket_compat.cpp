#include "net/socket_compat.h"

#ifndef _WIN32
#include <fcntl.h>

#include <cerrno>
#endif

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

bool connect_with_timeout(SocketHandle socket, const sockaddr_in& server, int timeout_ms) {
    // A blocking connect() cannot be interrupted, so connect in non-blocking mode and wait with select().
#ifdef _WIN32
    u_long non_blocking = 1;
    if (ioctlsocket(socket, FIONBIO, &non_blocking) != 0) {
        return false;
    }
    const int rc = connect(socket, reinterpret_cast<const sockaddr*>(&server), sizeof(server));
    const bool in_progress = rc != 0 && WSAGetLastError() == WSAEWOULDBLOCK;
#else
    const int flags = fcntl(socket, F_GETFL, 0);
    if (flags < 0 || fcntl(socket, F_SETFL, flags | O_NONBLOCK) < 0) {
        return false;
    }
    const int rc = connect(socket, reinterpret_cast<const sockaddr*>(&server), sizeof(server));
    const bool in_progress = rc != 0 && errno == EINPROGRESS;
#endif
    if (rc != 0 && !in_progress) {
        return false;
    }

    if (rc != 0) {
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(socket, &writable);
        // Windows reports a failed connect in the except set instead of the write set.
        fd_set failed;
        FD_ZERO(&failed);
        FD_SET(socket, &failed);

        timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        if (select(static_cast<int>(socket) + 1, nullptr, &writable, &failed, &timeout) <= 0) {
            return false;
        }

        int error = 0;
        SockLen error_length = sizeof(error);
        if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &error_length) != 0 ||
            error != 0) {
            return false;
        }
    }

    // Later send/recv calls are plain blocking calls guarded by wait_readable().
#ifdef _WIN32
    non_blocking = 0;
    return ioctlsocket(socket, FIONBIO, &non_blocking) == 0;
#else
    return fcntl(socket, F_SETFL, flags) == 0;
#endif
}

}  // namespace dns::net
