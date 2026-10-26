#include "net/transport.h"

#include <chrono>

#include "net/socket_compat.h"

namespace dns {

namespace {

constexpr size_t kMaxUdpResponse = 4096;

uint16_t read_id(const std::vector<uint8_t>& packet) {
    return static_cast<uint16_t>((packet[0] << 8) | packet[1]);
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

}  // namespace dns
