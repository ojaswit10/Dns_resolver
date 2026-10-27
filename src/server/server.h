#pragma once

// Caching DNS server: listens for queries from clients (the OS, nslookup, a
// browser), resolves them iteratively with Resolver, and sends the answers back.

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "cache/cache.h"
#include "dns/message.h"
#include "net/socket_compat.h"
#include "resolver/resolver.h"

namespace dns {

struct ServerOptions {
    std::string listen_ip = "127.0.0.1";
    uint16_t port = 53;      // 0 = any free port (used by tests)
    int max_in_flight = 64;  // queries resolved at the same time; extra ones are dropped
    bool log_queries = true;
    bool log_trace = false;  // also print every resolver step
    ResolverOptions resolver;
};

// Builds the reply to `query` from a resolution result. The reply is cut down
// to fit `max_size` bytes, setting TC if the answer did not fit.
std::vector<uint8_t> build_response(const Message& query, const ResolveResult& result, size_t max_size);

class Server {
public:
    Server(Cache& cache, ServerOptions options = {});
    ~Server();

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Opens the listening socket. On failure returns false and error() says why.
    bool start();

    // Serves queries until stop() is called, then waits for in-flight queries.
    void run();

    // Safe to call from any thread.
    void stop();

    // Handles one raw query packet and returns the raw reply, or nothing if the
    // packet should be dropped. Blocks while the name is resolved.
    std::optional<std::vector<uint8_t>> handle_packet(const std::vector<uint8_t>& packet, const std::string& client);

    uint16_t port() const { return port_; }
    const std::string& error() const { return error_; }

private:
    void serve_one(std::vector<uint8_t> packet, sockaddr_in client);
    void print(const std::string& line);

    Cache& cache_;
    ServerOptions options_;
    net::SocketHandle socket_ = net::kInvalidSocket;
    uint16_t port_ = 0;
    std::string error_;
    std::atomic<bool> stopping_{false};

    std::mutex cache_mutex_;
    std::mutex send_mutex_;
    std::mutex print_mutex_;

    std::mutex in_flight_mutex_;
    std::condition_variable in_flight_done_;
    int in_flight_ = 0;
};

}  // namespace dns
