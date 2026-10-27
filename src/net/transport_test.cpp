// Tests the transport against fake nameservers running on loopback, so no internet is needed.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <thread>
#include <vector>

#include "common/check.h"
#include "dns/codec.h"
#include "net/socket_compat.h"
#include "net/transport.h"

using namespace dns;

namespace {

// Fake servers give up after this, so a failing test cannot hang forever.
constexpr int kServerWaitMs = 3000;

TransportOptions make_options(uint16_t port, int timeout_ms, int attempts) {
    TransportOptions options;
    options.port = port;
    options.timeout_ms = timeout_ms;
    options.attempts = attempts;
    return options;
}

// Binds a loopback socket to ip:port (port 0 = any free port) and writes the port in use back to `port`.
net::SocketHandle open_socket(int type, const char* ip, uint16_t& port) {
    const net::SocketHandle socket = ::socket(AF_INET, type, 0);
    if (socket == net::kInvalidSocket) {
        return net::kInvalidSocket;
    }
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, ip, &address.sin_addr);
    net::SockLen length = sizeof(address);
    if (bind(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
        (type == SOCK_STREAM && listen(socket, 1) != 0) ||
        getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
        net::close_socket(socket);
        return net::kInvalidSocket;
    }
    port = ntohs(address.sin_port);
    return socket;
}

// One UDP socket per address in `ips`, all on the same port (the transport uses one port for every server).
std::vector<net::SocketHandle> open_udp_group(const std::vector<const char*>& ips, uint16_t& port) {
    for (int attempt = 0; attempt < 20; ++attempt) {
        port = 0;
        std::vector<net::SocketHandle> sockets;
        for (const char* ip : ips) {
            const net::SocketHandle socket = open_socket(SOCK_DGRAM, ip, port);
            if (socket == net::kInvalidSocket) {
                break;
            }
            sockets.push_back(socket);
        }
        if (sockets.size() == ips.size()) {
            return sockets;
        }
        for (const net::SocketHandle socket : sockets) {
            net::close_socket(socket);
        }
    }
    return {};
}

// A TCP listener and a UDP socket on the same loopback port, like a real nameserver.
bool open_tcp_and_udp(net::SocketHandle& tcp, net::SocketHandle& udp, uint16_t& port) {
    for (int attempt = 0; attempt < 20; ++attempt) {
        port = 0;
        tcp = open_socket(SOCK_STREAM, "127.0.0.1", port);
        if (tcp == net::kInvalidSocket) {
            continue;
        }
        udp = open_socket(SOCK_DGRAM, "127.0.0.1", port);
        if (udp != net::kInvalidSocket) {
            return true;
        }
        net::close_socket(tcp);
    }
    return false;
}

bool receive_datagram(net::SocketHandle socket, std::vector<uint8_t>& packet, sockaddr_in& from) {
    if (!net::wait_readable(socket, kServerWaitMs)) {
        return false;
    }
    std::vector<uint8_t> buffer(4096);
    net::SockLen from_length = sizeof(from);
    const auto received = recvfrom(socket, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                                   reinterpret_cast<sockaddr*>(&from), &from_length);
    if (received <= 0) {
        return false;
    }
    packet.assign(buffer.begin(), buffer.begin() + received);
    return true;
}

void send_datagram(net::SocketHandle socket, const sockaddr_in& to, const std::vector<uint8_t>& packet) {
    (void)sendto(socket, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
                 reinterpret_cast<const sockaddr*>(&to), sizeof(to));
}

// A valid reply to `query`: either truncated (TC set, no answers) or carrying one A record.
std::vector<uint8_t> make_response(const std::vector<uint8_t>& query, bool truncated) {
    Message message = decode(query);
    message.header.qr = true;
    message.header.tc = truncated;
    if (!truncated) {
        ResourceRecord record;
        record.name = message.questions.at(0).name;
        record.type = RecordType::A;
        record.ttl = 60;
        record.rdata = {93, 184, 216, 34};
        message.answers.push_back(record);
    }
    return encode(message);
}

std::vector<uint8_t> make_test_query() {
    return encode(make_query(0x1234, "example.com", RecordType::A));
}

bool receive_exact(net::SocketHandle socket, uint8_t* out, std::size_t count) {
    std::size_t done = 0;
    while (done < count) {
        if (!net::wait_readable(socket, kServerWaitMs)) {
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

void send_bytes(net::SocketHandle socket, const uint8_t* data, std::size_t count) {
    (void)send(socket, reinterpret_cast<const char*>(data), static_cast<int>(count), 0);
}

// Accepts one TCP connection and answers one query. `split` dribbles the reply out in pieces, because a
// real TCP stream does not promise to deliver a message in one recv().
void serve_tcp_once(net::SocketHandle listener, bool split) {
    if (!net::wait_readable(listener, kServerWaitMs)) {
        return;
    }
    const net::SocketHandle connection = accept(listener, nullptr, nullptr);
    if (connection == net::kInvalidSocket) {
        return;
    }
    uint8_t prefix[2] = {0, 0};
    if (receive_exact(connection, prefix, 2)) {
        std::vector<uint8_t> query(static_cast<std::size_t>((prefix[0] << 8) | prefix[1]));
        if (receive_exact(connection, query.data(), query.size())) {
            const std::vector<uint8_t> response = make_response(query, false);
            std::vector<uint8_t> framed = {static_cast<uint8_t>(response.size() >> 8),
                                           static_cast<uint8_t>(response.size() & 0xFF)};
            framed.insert(framed.end(), response.begin(), response.end());
            if (split) {
                send_bytes(connection, framed.data(), 1);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                send_bytes(connection, framed.data() + 1, 5);
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                send_bytes(connection, framed.data() + 6, framed.size() - 6);
            } else {
                send_bytes(connection, framed.data(), framed.size());
            }
        }
    }
    net::close_socket(connection);
}

void test_udp_reply() {
    uint16_t port = 0;
    const auto sockets = open_udp_group({"127.0.0.1"}, port);
    CHECK(sockets.size() == 1);
    if (sockets.empty()) {
        return;
    }

    std::thread server([&] {
        std::vector<uint8_t> query;
        sockaddr_in from{};
        if (receive_datagram(sockets[0], query, from)) {
            send_datagram(sockets[0], from, make_response(query, false));
        }
    });
    const auto reply = send_udp("127.0.0.1", make_test_query(), make_options(port, 1000, 1));
    server.join();

    CHECK(reply.has_value());
    if (reply) {
        const Message message = decode(*reply);
        CHECK(message.header.id == 0x1234);
        CHECK(message.header.qr);
        CHECK(message.answers.size() == 1);
    }
    net::close_socket(sockets[0]);
}

void test_udp_ignores_wrong_id() {
    uint16_t port = 0;
    const auto sockets = open_udp_group({"127.0.0.1"}, port);
    CHECK(sockets.size() == 1);
    if (sockets.empty()) {
        return;
    }

    std::thread server([&] {
        std::vector<uint8_t> query;
        sockaddr_in from{};
        if (receive_datagram(sockets[0], query, from)) {
            std::vector<uint8_t> forged = make_response(query, false);
            forged[0] ^= 0xFF;  // wrong ID: must be dropped, not returned
            send_datagram(sockets[0], from, forged);
            send_datagram(sockets[0], from, make_response(query, false));
        }
    });
    const auto reply = send_udp("127.0.0.1", make_test_query(), make_options(port, 1000, 1));
    server.join();

    CHECK(reply.has_value());
    if (reply) {
        CHECK(decode(*reply).header.id == 0x1234);
    }
    net::close_socket(sockets[0]);
}

void test_udp_retries_after_loss() {
    uint16_t port = 0;
    const auto sockets = open_udp_group({"127.0.0.1"}, port);
    CHECK(sockets.size() == 1);
    if (sockets.empty()) {
        return;
    }

    std::thread server([&] {
        std::vector<uint8_t> query;
        sockaddr_in from{};
        // Pretend the first query was lost; answer only the retry.
        if (receive_datagram(sockets[0], query, from) && receive_datagram(sockets[0], query, from)) {
            send_datagram(sockets[0], from, make_response(query, false));
        }
    });
    const auto reply = send_udp("127.0.0.1", make_test_query(), make_options(port, 300, 2));
    server.join();

    CHECK(reply.has_value());
    net::close_socket(sockets[0]);
}

void test_udp_timeout() {
    uint16_t port = 0;
    const auto sockets = open_udp_group({"127.0.0.1"}, port);
    CHECK(sockets.size() == 1);
    if (sockets.empty()) {
        return;
    }

    const auto start = std::chrono::steady_clock::now();
    const auto reply = send_udp("127.0.0.1", make_test_query(), make_options(port, 100, 2));
    const auto elapsed = std::chrono::steady_clock::now() - start;

    CHECK(!reply.has_value());
    CHECK(elapsed >= std::chrono::milliseconds(150));  // both attempts used their full timeout
    CHECK(elapsed < std::chrono::milliseconds(2000));
    net::close_socket(sockets[0]);
}

void test_truncated_reply_falls_back_to_tcp() {
    net::SocketHandle tcp = net::kInvalidSocket;
    net::SocketHandle udp = net::kInvalidSocket;
    uint16_t port = 0;
    CHECK(open_tcp_and_udp(tcp, udp, port));
    if (tcp == net::kInvalidSocket || udp == net::kInvalidSocket) {
        return;
    }

    std::thread udp_server([&] {
        std::vector<uint8_t> query;
        sockaddr_in from{};
        if (receive_datagram(udp, query, from)) {
            send_datagram(udp, from, make_response(query, true));
        }
    });
    std::thread tcp_server([&] { serve_tcp_once(tcp, false); });
    const auto reply = send_query("127.0.0.1", make_test_query(), make_options(port, 1000, 1));
    udp_server.join();
    tcp_server.join();

    CHECK(reply.has_value());
    if (reply) {
        const Message message = decode(*reply);
        CHECK(!message.header.tc);
        CHECK(message.answers.size() == 1);
    }
    net::close_socket(tcp);
    net::close_socket(udp);
}

void test_truncated_reply_without_tcp_fails() {
    uint16_t port = 0;
    const auto sockets = open_udp_group({"127.0.0.1"}, port);
    CHECK(sockets.size() == 1);
    if (sockets.empty()) {
        return;
    }

    std::thread server([&] {
        std::vector<uint8_t> query;
        sockaddr_in from{};
        if (receive_datagram(sockets[0], query, from)) {
            send_datagram(sockets[0], from, make_response(query, true));
        }
    });
    const auto reply = send_query("127.0.0.1", make_test_query(), make_options(port, 300, 1));
    server.join();

    // Nothing listens on TCP at this port, and a truncated answer is never handed back as if it were complete.
    CHECK(!reply.has_value());
    net::close_socket(sockets[0]);
}

void test_tcp_reassembles_split_reply() {
    uint16_t port = 0;
    const net::SocketHandle listener = open_socket(SOCK_STREAM, "127.0.0.1", port);
    CHECK(listener != net::kInvalidSocket);
    if (listener == net::kInvalidSocket) {
        return;
    }

    std::thread server([&] { serve_tcp_once(listener, true); });
    const auto reply = send_tcp("127.0.0.1", make_test_query(), make_options(port, 2000, 1));
    server.join();

    CHECK(reply.has_value());
    if (reply) {
        CHECK(decode(*reply).answers.size() == 1);
    }
    net::close_socket(listener);
}

void test_tcp_connection_refused() {
    uint16_t port = 0;
    // Bind and close to find a port that nothing is listening on.
    net::close_socket(open_socket(SOCK_STREAM, "127.0.0.1", port));
    CHECK(!send_tcp("127.0.0.1", make_test_query(), make_options(port, 300, 1)).has_value());
}

void test_query_servers_skips_bad_servers() {
    uint16_t port = 0;
    const auto sockets = open_udp_group({"127.0.0.1"}, port);
    CHECK(sockets.size() == 1);
    if (sockets.empty()) {
        return;
    }

    // One fake server plays four different nameservers: the same address is listed four times, and each
    // query that arrives is handled as the next server in the list would behave.
    int queries_seen = 0;
    std::thread server([&] {
        std::vector<uint8_t> query;
        sockaddr_in from{};
        // 1st: silent (times out). 2nd: garbage. 3rd: a query instead of a response. 4th: a proper answer.
        for (int i = 0; i < 4 && receive_datagram(sockets[0], query, from); ++i) {
            ++queries_seen;
            if (i == 1) {
                // Right ID so the transport accepts it, but far too short to decode.
                send_datagram(sockets[0], from, {query[0], query[1], 0x80, 0x00, 0xFF});
            } else if (i == 2) {
                send_datagram(sockets[0], from, query);
            } else if (i == 3) {
                send_datagram(sockets[0], from, make_response(query, false));
            }
        }
    });

    const std::vector<std::string> servers = {"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"};
    const auto reply = query_servers(servers, make_test_query(), make_options(port, 150, 1));
    server.join();

    CHECK(reply.has_value());
    CHECK(queries_seen == 4);  // every bad server was skipped, none ended the search early
    if (reply) {
        CHECK(reply->server_ip == "127.0.0.1");
        CHECK(reply->message.header.id == 0x1234);
        CHECK(reply->message.answers.size() == 1);
    }
    net::close_socket(sockets[0]);
}

void test_query_servers_gives_up() {
    CHECK(!query_servers({}, make_test_query()).has_value());

    uint16_t port = 0;
    const auto sockets = open_udp_group({"127.0.0.1"}, port);
    CHECK(sockets.size() == 1);
    if (sockets.empty()) {
        return;
    }
    CHECK(!query_servers({"127.0.0.1"}, make_test_query(), make_options(port, 100, 1)).has_value());
    net::close_socket(sockets[0]);
}

}  // namespace

int main() {
    // Windows needs Winsock started before the fake servers open their sockets.
    CHECK(net::init_sockets());
    test_udp_reply();
    test_udp_ignores_wrong_id();
    test_udp_retries_after_loss();
    test_udp_timeout();
    test_truncated_reply_falls_back_to_tcp();
    test_truncated_reply_without_tcp_fails();
    test_tcp_reassembles_split_reply();
    test_tcp_connection_refused();
    test_query_servers_skips_bad_servers();
    test_query_servers_gives_up();
    return dns::test::report();
}
