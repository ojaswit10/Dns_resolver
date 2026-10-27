#pragma once

// Sending DNS queries to a nameserver. Minimal version: UDP over IPv4, one
// server per call. TCP fallback and server selection are added on top of this.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dns {

struct TransportOptions {
    int timeout_ms = 2000;  // per attempt
    int attempts = 2;       // total sends before giving up
    uint16_t port = 53;
};

// Sends `query` to `server_ip` (dotted IPv4) and returns the raw response.
// Replies whose ID does not match the query's ID are ignored.
// Returns std::nullopt on timeout or socket error.
std::optional<std::vector<uint8_t>> send_udp(const std::string& server_ip, const std::vector<uint8_t>& query,
                                             const TransportOptions& options = {});

// Sends `query` over TCP (2-byte length prefix, RFC 1035 section 4.2.2) and returns the raw response.
// Returns std::nullopt on connect failure, timeout, short read or a reply whose ID does not match.
std::optional<std::vector<uint8_t>> send_tcp(const std::string& server_ip, const std::vector<uint8_t>& query,
                                             const TransportOptions& options = {});

}  // namespace dns
