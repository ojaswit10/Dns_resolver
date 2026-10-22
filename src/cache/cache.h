#pragma once

#include <chrono>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "dns/message.h"

namespace dns {

struct CacheEntry {
    ResourceRecord record;
    std::chrono::steady_clock::time_point expires_at;
};

struct NegativeCacheEntry {
    Rcode rcode;
    std::chrono::steady_clock::time_point expires_at;
};

class Cache {
public:
    // Returns valid records for a name and type, or an empty vector on a miss.
    std::vector<ResourceRecord> get(const std::string& name, RecordType type);

    // Stores a record until its TTL expires.
    void put(const ResourceRecord& record);

    // Removes expired records from the cache.
    void remove_expired();

    // Stores a negative DNS response using the SOA-derived TTL.
    void put_negative(
        const std::string& name,
        RecordType type,
        Rcode rcode,
        const ResourceRecord& soa_record);

    // Returns a valid negative response, or std::nullopt on a miss.
    std::optional<Rcode> get_negative(const std::string& name, RecordType type);

private:
    std::unordered_map<std::string, std::vector<CacheEntry>> entries_;
    std::unordered_map<std::string, NegativeCacheEntry> negative_entries_;
};

}  // namespace dns
