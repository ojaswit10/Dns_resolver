
#include "cache.h"

#include <algorithm>
#include <chrono>
#include <cstdint>

namespace dns {
namespace {

std::string make_key(const std::string& name, RecordType type, uint16_t klass) {
    return normalize_name(name) + "|" +
           std::to_string(static_cast<uint16_t>(type)) + "|" +
           std::to_string(klass);
}

std::string make_nxdomain_key(const std::string& name) {
    return "NX|" + normalize_name(name);
}

std::string make_nodata_key(const std::string& name, RecordType type) {
    return "ND|" + make_key(name, type, static_cast<uint16_t>(RecordClass::IN));
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
                std::chrono::duration_cast<std::chrono::seconds>(
                    entry->expires_at - now).count());
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
    if (record.ttl == 0) {
        return;
    }

    const auto key = make_key(record.name, record.type, record.klass);
    const auto expires_at = std::chrono::steady_clock::now() +
                            std::chrono::seconds(record.ttl);

    entries_[key].push_back({record, expires_at});

    // New positive data invalidates matching negative cache entries.
    negative_entries_.erase(make_nxdomain_key(record.name));
    negative_entries_.erase(make_nodata_key(record.name, record.type));
}

void Cache::put_negative(
    const std::string& name,
    RecordType type,
    Rcode rcode,
    const ResourceRecord& soa_record) {
    if ((rcode != Rcode::NxDomain && rcode != Rcode::NoError) ||
        soa_record.type != RecordType::SOA) {
        return;
    }

    const auto ttl = std::min(soa_record.ttl, soa_record.soa.minimum);
    if (ttl == 0) {
        return;
    }

    const auto expires_at = std::chrono::steady_clock::now() +
                            std::chrono::seconds(ttl);

    const auto key = rcode == Rcode::NxDomain
        ? make_nxdomain_key(name)
        : make_nodata_key(name, type);

    negative_entries_[key] = {rcode, expires_at};
}

std::optional<Rcode> Cache::get_negative(const std::string& name, RecordType type) {
    const auto now = std::chrono::steady_clock::now();

    const auto nx_key = make_nxdomain_key(name);
    auto nx_it = negative_entries_.find(nx_key);

    if (nx_it != negative_entries_.end()) {
        if (nx_it->second.expires_at > now) {
            return nx_it->second.rcode;
        }
        negative_entries_.erase(nx_it);
    }

    const auto nodata_key = make_nodata_key(name, type);
    auto nodata_it = negative_entries_.find(nodata_key);

    if (nodata_it != negative_entries_.end()) {
        if (nodata_it->second.expires_at > now) {
            return nodata_it->second.rcode;
        }
        negative_entries_.erase(nodata_it);
    }

    return std::nullopt;
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

    for (auto it = negative_entries_.begin(); it != negative_entries_.end();) {
        if (it->second.expires_at <= now) {
            it = negative_entries_.erase(it);
        } else {
            ++it;
        }
    }
}

}  // namespace dns

