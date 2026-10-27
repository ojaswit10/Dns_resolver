#include "net/transport.h"

#include <chrono>
#include <cstddef>
#include <utility>

#include "net/socket_compat.h"

namespace dns {

namespace {

constexpr size_t kMaxUdpResponse = 4096;

uint16_t read_id(const std::vector<uint8_t>& packet) {
    return static_cast<uint16_t>((packet[0] << 8) | packet[1]);
}

// The TCP length prefix is 16 bits, so no DNS message can be larger than this.
constexpr std::size_t kMaxTcpMessage = 65535;

// A write to a closed TCP connection would otherwise kill the process with SIGPIPE on Linux.
#ifdef MSG_NOSIGNAL
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

bool write_all(net::SocketHandle socket, const std::vector<uint8_t>& data) {
    std::size_t done = 0;
    while (done < data.size()) {
        const auto sent = send(socket, reinterpret_cast<const char*>(data.data() + done),
                               static_cast<int>(data.size() - done), kSendFlags);
        if (sent <= 0) {
            return false;
        }
        done += static_cast<std::size_t>(sent);
    }
    return true;
}

// TCP is a byte stream, so one recv() may return only part of a message: keep reading until `count` bytes
// have arrived or the deadline passes.
bool read_exact(net::SocketHandle socket, uint8_t* out, std::size_t count,
                std::chrono::steady_clock::time_point deadline) {
    std::size_t done = 0;
    while (done < count) {
        const auto remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (remaining <= 0 || !net::wait_readable(socket, static_cast<int>(remaining))) {
            return false;
        }
        const auto received = recv(socket, reinterpret_cast<char*>(out + done), static_cast<int>(count - done), 0);
        if (received <= 0) {
            return false;
        }
        done += static_cast<std::size_t>(received);
    }
    return true;
}

}  // namespace

std::optional<std::vector<uint8_t>> send_udp(const std::string& server_ip, const std::vector<uint8_t>& query,
                                             const TransportOptions& options) {
    if (query.size() < 2 || !net::init_sockets()) {
        return std::nullopt;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(options.port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server.sin_addr) != 1) {
        return std::nullopt;
    }

    const net::SocketHandle socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket == net::kInvalidSocket) {
        return std::nullopt;
    }

    const uint16_t query_id = read_id(query);
    std::vector<uint8_t> buffer(kMaxUdpResponse);
    std::optional<std::vector<uint8_t>> result;

    for (int attempt = 0; attempt < options.attempts && !result; ++attempt) {
        const auto sent = sendto(socket, reinterpret_cast<const char*>(query.data()), static_cast<int>(query.size()), 0,
                                 reinterpret_cast<const sockaddr*>(&server), sizeof(server));
        if (sent < 0) {
            break;
        }

        // Keep reading until the deadline: replies from another address or with
        // the wrong ID are dropped.
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(options.timeout_ms);
        while (!result) {
            const auto remaining =
                std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now())
                    .count();
            if (remaining <= 0 || !net::wait_readable(socket, static_cast<int>(remaining))) {
                break;
            }
            sockaddr_in from{};
            net::SockLen from_length = sizeof(from);
            const auto received =
                recvfrom(socket, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                         reinterpret_cast<sockaddr*>(&from), &from_length);
            const bool from_server = from.sin_addr.s_addr == server.sin_addr.s_addr && from.sin_port == server.sin_port;
            if (received >= 2 && from_server) {
                std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + received);
                if (read_id(packet) == query_id) {
                    result = std::move(packet);
                }
            }
        }
    }

    net::close_socket(socket);
    return result;
}

std::optional<std::vector<uint8_t>> send_tcp(const std::string& server_ip, const std::vector<uint8_t>& query,
                                             const TransportOptions& options) {
    if (query.size() < 2 || query.size() > kMaxTcpMessage || !net::init_sockets()) {
        return std::nullopt;
    }

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(options.port);
    if (inet_pton(AF_INET, server_ip.c_str(), &server.sin_addr) != 1) {
        return std::nullopt;
    }

    const net::SocketHandle socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket == net::kInvalidSocket) {
        return std::nullopt;
    }

    std::optional<std::vector<uint8_t>> result;
    if (net::connect_with_timeout(socket, server, options.timeout_ms)) {
        std::vector<uint8_t> framed;
        framed.reserve(query.size() + 2);
        framed.push_back(static_cast<uint8_t>(query.size() >> 8));
        framed.push_back(static_cast<uint8_t>(query.size() & 0xFF));
        framed.insert(framed.end(), query.begin(), query.end());

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(options.timeout_ms);
        uint8_t prefix[2] = {0, 0};
        if (write_all(socket, framed) && read_exact(socket, prefix, 2, deadline)) {
            const std::size_t length = static_cast<std::size_t>((prefix[0] << 8) | prefix[1]);
            std::vector<uint8_t> packet(length);
            // A reply shorter than the header cannot be valid, and a wrong ID is not our answer.
            if (length >= 2 && read_exact(socket, packet.data(), length, deadline) &&
                read_id(packet) == read_id(query)) {
                result = std::move(packet);
            }
        }
    }

    net::close_socket(socket);
    return result;
}

}  // namespace dns
