#include "cache.h"

#include <chrono>
#include <cstdint>

namespace dns {
namespace {

std::string make_key(const std::string& name, RecordType type, uint16_t klass) {
    return normalize_name(name) + "|" + std::to_string(static_cast<uint16_t>(type)) + "|" + std::to_string(klass);
}

}  // namespace

std::vector<ResourceRecord> Cache::get(const std::string& name, RecordType type) {
    const auto key = make_key(name, type, static_cast<uint16_t>(RecordClass::IN));

    auto it = entries_.find(key);

    if (it == entries_.end()) {
        return {};
    }

    const auto now = std::chrono::steady_clock::now();
    std::vector<ResourceRecord> result;
    auto& records = it->second;

    for (auto entry = records.begin(); entry != records.end();) {
        if (entry->expires_at <= now) {
            entry = records.erase(entry);
        } else {
            auto record = entry->record;
            record.ttl = static_cast<uint32_t>(
                std::chrono::duration_cast<std::chrono::seconds>(entry->expires_at - now).count());

            result.push_back(record);
            ++entry;
        }
    }

    if (records.empty()) {
        entries_.erase(it);
    }

    return result;
}

void Cache::put(const ResourceRecord& record) {
    const auto key = make_key(record.name, record.type, record.klass);
    const auto expires_at = std::chrono::steady_clock::now() + std::chrono::seconds(record.ttl);

    entries_[key].push_back({record, expires_at});
}

void Cache::remove_expired() {
    const auto now = std::chrono::steady_clock::now();

    for (auto it = entries_.begin(); it != entries_.end();) {
        auto& records = it->second;

        for (auto entry = records.begin(); entry != records.end();) {
            if (entry->expires_at <= now) {
                entry = records.erase(entry);
            } else {
                ++entry;
            }
        }

        if (records.empty()) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace dns
