#include "resolver/resolver.h"

#include <algorithm>
#include <utility>

#include "dns/codec.h"
#include "resolver/root_hints.h"

namespace dns {

namespace {

constexpr size_t kMaxGluelessLookups = 3;

std::string display(const std::string& name) {
    return name.empty() ? "." : name;
}

// True when `child` is `parent` or lies below it; every name is under the root "".
bool is_subdomain(const std::string& child, const std::string& parent) {
    const std::string c = normalize_name(child);
    const std::string p = normalize_name(parent);
    if (p.empty() || c == p) {
        return true;
    }
    return c.size() > p.size() && c.compare(c.size() - p.size(), p.size(), p) == 0 && c[c.size() - p.size() - 1] == '.';
}

std::string parent_of(const std::string& name) {
    const size_t dot = name.find('.');
    return dot == std::string::npos ? "" : name.substr(dot + 1);
}

std::optional<ResourceRecord> find_soa(const std::vector<ResourceRecord>& records) {
    for (const ResourceRecord& record : records) {
        if (record.type == RecordType::SOA) {
            return record;
        }
    }
    return std::nullopt;
}

// Record data equality, ignoring TTL. Name-bearing types compare decoded names,
// because their raw rdata can hold compression pointers into another packet.
bool same_data(const ResourceRecord& a, const ResourceRecord& b) {
    if (a.type != b.type) {
        return false;
    }
    switch (a.type) {
        case RecordType::NS:
        case RecordType::CNAME: return names_equal(a.target, b.target);
        case RecordType::MX: return a.preference == b.preference && names_equal(a.target, b.target);
        case RecordType::SOA: return names_equal(a.soa.mname, b.soa.mname) && a.soa.serial == b.soa.serial;
        default: return a.rdata == b.rdata;
    }
}

}  // namespace

std::string to_string(ResolveStatus status) {
    switch (status) {
        case ResolveStatus::Ok: return "NOERROR";
        case ResolveStatus::NxDomain: return "NXDOMAIN";
        case ResolveStatus::NoData: return "NODATA";
        case ResolveStatus::ServFail: return "SERVFAIL";
    }
    return "UNKNOWN";
}

Resolver::Resolver(Cache* cache, ResolverOptions options)
    : cache_(cache), options_(std::move(options)), random_(std::random_device{}()) {}

ResolveResult Resolver::resolve(const std::string& name, RecordType type) {
    queries_ = 0;
    trace_.clear();

    ResolveResult result = resolve_at_depth(normalize_name(name), type, 0);
    result.upstream_queries = queries_;
    result.trace = std::move(trace_);
    trace_.clear();
    return result;
}

ResolveResult Resolver::resolve_at_depth(const std::string& name, RecordType type, int depth) {
    ResolveResult result;
    std::string current = name;

    for (int hop = 0; hop <= options_.max_cname_hops; ++hop) {
        if (cache_) {
            if (const auto negative = cache_->get_negative(current, type)) {
                result.status = *negative == Rcode::NxDomain ? ResolveStatus::NxDomain : ResolveStatus::NoData;
                log(depth, "cache: " + display(current) + " " + to_string(type) + " -> " + to_string(result.status));
                return result;
            }
            const std::vector<ResourceRecord> cached = cache_->get(current, type);
            if (!cached.empty()) {
                log(depth, "cache: " + display(current) + " " + to_string(type) + " -> " +
                               std::to_string(cached.size()) + " record(s)");
                result.answers.insert(result.answers.end(), cached.begin(), cached.end());
                result.status = ResolveStatus::Ok;
                return result;
            }
            if (type != RecordType::CNAME) {
                const std::vector<ResourceRecord> alias = cache_->get(current, RecordType::CNAME);
                if (!alias.empty()) {
                    log(depth, "cache: " + display(current) + " is an alias for " + display(alias[0].target));
                    result.answers.push_back(alias[0]);
                    current = normalize_name(alias[0].target);
                    continue;
                }
            }
        }

        ResolveResult step = walk(current, type, depth);
        result.answers.insert(result.answers.end(), step.answers.begin(), step.answers.end());
        if (step.status != ResolveStatus::Ok) {
            result.status = step.status;
            result.soa = step.soa;
            return result;
        }

        // The walk stopped at an alias whose target lives elsewhere: resolve the target next.
        const ResourceRecord& last = result.answers.back();
        if (last.type == RecordType::CNAME && type != RecordType::CNAME) {
            current = normalize_name(last.target);
            continue;
        }
        result.status = ResolveStatus::Ok;
        return result;
    }

    log(depth, "giving up: more than " + std::to_string(options_.max_cname_hops) + " CNAME hops");
    result.status = ResolveStatus::ServFail;
    return result;
}

ResolveResult Resolver::walk(const std::string& name, RecordType type, int depth) {
    ResolveResult result;
    ServerSet servers = closest_known_servers(name, depth);

    while (true) {
        const std::optional<Message> response = ask(servers, name, type, depth);
        if (!response) {
            log(depth, "  no usable reply from any server for zone " + display(servers.zone));
            result.status = ResolveStatus::ServFail;
            return result;
        }
        const Message& message = *response;

        // Follow the answer section: owner -> CNAME -> ... -> records of the wanted type.
        // Only records inside the asked server's zone are trusted.
        std::string owner = name;
        bool complete = false;
        for (size_t guard = 0; guard <= message.answers.size() && !complete; ++guard) {
            const ResourceRecord* alias = nullptr;
            for (const ResourceRecord& record : message.answers) {
                if (!names_equal(record.name, owner) || !is_subdomain(record.name, servers.zone)) {
                    continue;
                }
                if (record.type == type) {
                    result.answers.push_back(record);
                    complete = true;
                } else if (record.type == RecordType::CNAME && !alias) {
                    alias = &record;
                }
            }
            if (complete || !alias) {
                break;
            }
            result.answers.push_back(*alias);
            owner = normalize_name(alias->target);
        }
        cache_records(result.answers);

        if (message.header.rcode == Rcode::NxDomain) {
            result.status = ResolveStatus::NxDomain;
            result.soa = find_soa(message.authority);
            if (cache_ && result.soa) {
                cache_->put_negative(owner, type, Rcode::NxDomain, *result.soa);
            }
            log(depth, "  -> NXDOMAIN: " + display(owner) + " does not exist");
            return result;
        }

        if (!result.answers.empty()) {
            result.status = ResolveStatus::Ok;
            log(depth, "  -> answer: " + std::to_string(result.answers.size()) + " record(s)" +
                           (complete ? "" : ", alias leads to " + display(owner)));
            return result;
        }

        // Referral: NS records for a zone between the current zone and the name.
        std::string child_zone;
        std::vector<ResourceRecord> ns_records;
        for (const ResourceRecord& record : message.authority) {
            if (record.type != RecordType::NS || !is_subdomain(name, record.name) ||
                !is_subdomain(record.name, servers.zone) || names_equal(record.name, servers.zone)) {
                continue;
            }
            if (ns_records.empty()) {
                child_zone = normalize_name(record.name);
            }
            if (names_equal(record.name, child_zone)) {
                ns_records.push_back(record);
            }
        }

        if (!ns_records.empty()) {
            log(depth,
                "  -> referral to " + display(child_zone) + " (" + std::to_string(ns_records.size()) + " nameservers)");
            std::vector<std::string> ips = nameserver_ips(ns_records, message.additional, servers.zone, depth);
            if (ips.empty()) {
                log(depth, "  no addresses found for the nameservers of " + display(child_zone));
                result.status = ResolveStatus::ServFail;
                return result;
            }
            servers = ServerSet{child_zone, std::move(ips)};
            continue;
        }

        // No answer and no referral: the name exists but has no records of this type.
        result.soa = find_soa(message.authority);
        if (!result.soa && !message.header.aa) {
            log(depth, "  -> empty, non-authoritative reply (lame server)");
            result.status = ResolveStatus::ServFail;
            return result;
        }
        if (cache_ && result.soa) {
            cache_->put_negative(name, type, Rcode::NoError, *result.soa);
        }
        result.status = ResolveStatus::NoData;
        log(depth, "  -> NODATA: " + display(name) + " has no " + to_string(type) + " records");
        return result;
    }
}

Resolver::ServerSet Resolver::closest_known_servers(const std::string& name, int depth) {
    if (cache_) {
        for (std::string zone = name;; zone = parent_of(zone)) {
            ServerSet servers{zone, {}};
            for (const ResourceRecord& ns : cache_->get(zone, RecordType::NS)) {
                for (const ResourceRecord& a : cache_->get(ns.target, RecordType::A)) {
                    servers.ips.push_back(a.address);
                }
            }
            if (!servers.ips.empty()) {
                log(depth, "cache: start at known servers for " + display(zone));
                return servers;
            }
            if (zone.empty()) {
                break;
            }
        }
    }

    ServerSet roots{"", options_.root_servers};
    if (!roots.ips.empty()) {
        return roots;
    }
    // Start at a random root server so repeated runs spread their load.
    const size_t start = random_() % kRootServers.size();
    for (size_t i = 0; i < kRootServers.size(); ++i) {
        roots.ips.push_back(kRootServers[(start + i) % kRootServers.size()].ip);
    }
    return roots;
}

std::vector<std::string> Resolver::nameserver_ips(const std::vector<ResourceRecord>& ns_records,
                                                  const std::vector<ResourceRecord>& additional,
                                                  const std::string& parent_zone, int depth) {
    cache_records(ns_records);

    // Glue: addresses the parent sent along. Only trust ones inside the parent's zone.
    std::vector<ResourceRecord> glue;
    std::vector<std::string> ips;
    for (const ResourceRecord& ns : ns_records) {
        for (const ResourceRecord& record : additional) {
            if (record.type == RecordType::A && names_equal(record.name, ns.target) &&
                is_subdomain(record.name, parent_zone)) {
                glue.push_back(record);
                if (std::find(ips.begin(), ips.end(), record.address) == ips.end()) {
                    ips.push_back(record.address);
                }
            }
        }
    }
    cache_records(glue);
    if (!ips.empty()) {
        log(depth, "  glue: " + std::to_string(ips.size()) + " address(es)");
        return ips;
    }

    // No glue: look up a few nameserver names on their own, from the top.
    for (size_t i = 0; i < ns_records.size() && i < kMaxGluelessLookups; ++i) {
        if (depth + 1 > options_.max_depth) {
            log(depth, "  giving up: nameserver lookups nested too deeply");
            break;
        }
        const std::string& target = ns_records[i].target;
        log(depth, "  no glue, resolving nameserver " + display(target));
        const ResolveResult lookup = resolve_at_depth(normalize_name(target), RecordType::A, depth + 1);
        for (const ResourceRecord& record : lookup.answers) {
            if (record.type == RecordType::A) {
                ips.push_back(record.address);
            }
        }
        if (!ips.empty()) {
            break;
        }
    }
    return ips;
}

std::optional<Message> Resolver::ask(const ServerSet& servers, const std::string& name, RecordType type, int depth) {
    for (const std::string& ip : servers.ips) {
        if (queries_ >= options_.max_queries) {
            log(depth, "  giving up: query limit of " + std::to_string(options_.max_queries) + " reached");
            return std::nullopt;
        }
        ++queries_;
        log(depth, "ask " + ip + " [" + display(servers.zone) + "] for " + display(name) + " " + to_string(type));

        const std::vector<uint8_t> query = encode(make_query(static_cast<uint16_t>(random_()), name, type));
        const std::optional<std::vector<uint8_t>> reply =
            options_.query ? options_.query(ip, query) : send_udp(ip, query, options_.transport);
        if (!reply) {
            log(depth, "  no reply, trying next server");
            continue;
        }

        Message message;
        try {
            message = decode(*reply);
        } catch (const ParseError& error) {
            log(depth, std::string("  malformed reply (") + error.what() + "), trying next server");
            continue;
        }

        const bool matches = message.header.qr && message.questions.size() == 1 &&
                             names_equal(message.questions[0].name, name) && message.questions[0].type == type;
        if (!matches) {
            log(depth, "  reply is for a different question, trying next server");
            continue;
        }
        if (message.header.rcode != Rcode::NoError && message.header.rcode != Rcode::NxDomain) {
            log(depth, "  " + to_string(message.header.rcode) + ", trying next server");
            continue;
        }
        return message;
    }
    return std::nullopt;
}

void Resolver::cache_records(const std::vector<ResourceRecord>& records) {
    if (!cache_) {
        return;
    }
    for (const ResourceRecord& record : records) {
        if (record.type == RecordType::OPT) {
            continue;
        }
        // Skip records already cached so repeated walks don't store duplicates.
        const std::vector<ResourceRecord> existing = cache_->get(record.name, record.type);
        const bool known = std::any_of(existing.begin(), existing.end(),
                                       [&](const ResourceRecord& other) { return same_data(record, other); });
        if (!known) {
            cache_->put(record);
        }
    }
}

void Resolver::log(int depth, const std::string& line) {
    trace_.push_back(std::string(static_cast<size_t>(depth) * 4, ' ') + line);
}

}  // namespace dns
