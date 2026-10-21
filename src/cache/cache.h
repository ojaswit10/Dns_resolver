#pragma once

#include <chrono>
#include <string>
#include <unordered_map>
#include <vector>

#include "dns/message.h"

namespace dns {

struct CacheEntry {
    ResourceRecord record;
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

private:
    std::unordered_map<std::string, std::vector<CacheEntry>> entries_;
};

}  // namespace dns
