#pragma once

// Iterative DNS resolution: walks root -> TLD -> authoritative servers itself
// instead of forwarding to a recursive resolver like 8.8.8.8.

#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "cache/cache.h"
#include "dns/message.h"
#include "net/transport.h"

namespace dns {

// Sends raw query bytes to a server IP and returns the raw reply. Defaults to
// send_udp(); tests swap in a fake so they run without the internet.
using QueryFunction =
    std::function<std::optional<std::vector<uint8_t>>(const std::string& server_ip, const std::vector<uint8_t>& query)>;

struct ResolverOptions {
    int max_queries = 60;    // upstream queries per resolve() call, across all sub-lookups
    int max_cname_hops = 8;  // aliases followed before giving up
    int max_depth = 4;       // nesting of lookups for nameservers that came without glue
    TransportOptions transport = {1500, 1, 53};
    QueryFunction query;                    // empty = real UDP
    std::vector<std::string> root_servers;  // empty = built-in root hints

    // Set when several Resolvers on different threads share one Cache: every
    // cache call is made while holding this lock. Network calls are not.
    std::mutex* cache_mutex = nullptr;
};

enum class ResolveStatus {
    Ok,        // answers holds the records (after any CNAMEs)
    NxDomain,  // the name does not exist
    NoData,    // the name exists but has no records of this type
    ServFail,  // no server gave a usable answer, or a limit was hit
};

std::string to_string(ResolveStatus status);

struct ResolveResult {
    ResolveStatus status = ResolveStatus::ServFail;
    std::vector<ResourceRecord> answers;  // CNAME chain first, then the final records
    std::optional<ResourceRecord> soa;    // set for NxDomain / NoData when the server sent one
    int upstream_queries = 0;
    std::vector<std::string> trace;  // one human-readable line per step
};

class Resolver {
public:
    // `cache` may be null to always resolve from the root.
    explicit Resolver(Cache* cache = nullptr, ResolverOptions options = {});

    ResolveResult resolve(const std::string& name, RecordType type);

private:
    struct ServerSet {
        std::string zone;              // zone these servers are authoritative for
        std::vector<std::string> ips;  // IPv4 addresses to try in order
    };

    // Follows CNAMEs, using the cache first and walk() for anything it lacks.
    ResolveResult resolve_at_depth(const std::string& name, RecordType type, int depth);

    // One walk down the hierarchy until an answer, alias or negative response.
    ResolveResult walk(const std::string& name, RecordType type, int depth);

    ServerSet closest_known_servers(const std::string& name, int depth);

    // Addresses for a referral's nameservers: glue first, then separate lookups.
    std::vector<std::string> nameserver_ips(const std::vector<ResourceRecord>& ns_records,
                                            const std::vector<ResourceRecord>& additional,
                                            const std::string& parent_zone, int depth);

    // Tries each server in turn; returns the first usable reply.
    std::optional<Message> ask(const ServerSet& servers, const std::string& name, RecordType type, int depth);

    void cache_records(const std::vector<ResourceRecord>& records);
    std::unique_lock<std::mutex> lock_cache();  // no-op lock when cache_mutex is unset
    void log(int depth, const std::string& line);

    Cache* cache_;
    ResolverOptions options_;
    std::mt19937 random_;

    // Reset by every resolve() call and shared by its nested lookups.
    int queries_ = 0;
    std::vector<std::string> trace_;
};

}  // namespace dns
