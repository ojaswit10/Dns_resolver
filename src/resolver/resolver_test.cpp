// Resolver tests against a fake DNS hierarchy, so they run without the internet:
//
//   root          10.0.0.1   delegates "test" to ns.test (glue 10.0.0.2)
//   test          10.0.0.2   delegates example.test (with glue), provider.test (with glue),
//                            and other.test to ns.provider.test (no glue)
//   example.test  10.0.0.3
//   provider.test 10.0.0.4   also serves other.test

#include "resolver/resolver.h"

#include <functional>
#include <map>

#include "common/check.h"
#include "dns/codec.h"

using namespace dns;

namespace {

ResourceRecord a_record(const std::string& name, const std::string& address, uint32_t ttl = 300) {
    ResourceRecord record;
    record.name = name;
    record.type = RecordType::A;
    record.ttl = ttl;
    record.address = address;
    // Dotted text -> 4 bytes.
    size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        const size_t dot = address.find('.', start);
        record.rdata.push_back(static_cast<uint8_t>(std::stoi(address.substr(start, dot - start))));
        start = dot + 1;
    }
    return record;
}

ResourceRecord name_record(const std::string& name, RecordType type, const std::string& target, uint32_t ttl = 300) {
    ResourceRecord record;
    record.name = name;
    record.type = type;
    record.ttl = ttl;
    record.target = target;
    return record;
}

ResourceRecord soa_record(const std::string& zone) {
    ResourceRecord record;
    record.name = zone;
    record.type = RecordType::SOA;
    record.ttl = 600;
    record.soa = SoaData{"ns1." + zone, "admin." + zone, 1, 3600, 600, 86400, 300};
    return record;
}

bool ends_with(const std::string& name, const std::string& suffix) {
    return name == suffix ||
           (name.size() > suffix.size() && name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0 &&
            name[name.size() - suffix.size() - 1] == '.');
}

// Fills `reply` (already a response to the question) for one fake server.
using ServerLogic = std::function<void(const Question& question, Message& reply)>;

class FakeNetwork {
public:
    FakeNetwork() {
        servers_["10.0.0.1"] = [](const Question& q, Message& reply) {
            if (ends_with(q.name, "test")) {
                reply.authority.push_back(name_record("test", RecordType::NS, "ns.test"));
                reply.additional.push_back(a_record("ns.test", "10.0.0.2"));
            } else {
                reply.header.rcode = Rcode::NxDomain;
            }
        };

        servers_["10.0.0.2"] = [](const Question& q, Message& reply) {
            if (ends_with(q.name, "example.test")) {
                reply.authority.push_back(name_record("example.test", RecordType::NS, "ns1.example.test"));
                reply.additional.push_back(a_record("ns1.example.test", "10.0.0.3"));
            } else if (ends_with(q.name, "provider.test")) {
                reply.authority.push_back(name_record("provider.test", RecordType::NS, "ns.provider.test"));
                reply.additional.push_back(a_record("ns.provider.test", "10.0.0.4"));
            } else if (ends_with(q.name, "other.test")) {
                reply.authority.push_back(name_record("other.test", RecordType::NS, "ns.provider.test"));
            } else {
                reply.header.rcode = Rcode::NxDomain;
                reply.authority.push_back(soa_record("test"));
            }
        };

        servers_["10.0.0.3"] = [](const Question& q, Message& reply) {
            reply.header.aa = true;
            if (q.name == "www.example.test" && q.type == RecordType::A) {
                reply.answers.push_back(a_record("www.example.test", "1.2.3.4"));
            } else if (q.name == "www.example.test") {
                reply.authority.push_back(soa_record("example.test"));  // NODATA
            } else if (q.name == "alias.example.test") {
                reply.answers.push_back(name_record("alias.example.test", RecordType::CNAME, "www.example.test"));
                reply.answers.push_back(a_record("www.example.test", "1.2.3.4"));
            } else if (q.name == "ext.example.test") {
                reply.answers.push_back(name_record("ext.example.test", RecordType::CNAME, "host.other.test"));
                // Out-of-zone record this server has no authority for: must be ignored.
                reply.answers.push_back(a_record("host.other.test", "6.6.6.6"));
            } else if (q.name == "loop1.example.test") {
                reply.answers.push_back(name_record("loop1.example.test", RecordType::CNAME, "loop2.example.test"));
                reply.answers.push_back(name_record("loop2.example.test", RecordType::CNAME, "loop1.example.test"));
            } else if (q.name == "loop2.example.test") {
                reply.answers.push_back(name_record("loop2.example.test", RecordType::CNAME, "loop1.example.test"));
            } else {
                reply.header.rcode = Rcode::NxDomain;
                reply.authority.push_back(soa_record("example.test"));
            }
        };

        servers_["10.0.0.4"] = [](const Question& q, Message& reply) {
            reply.header.aa = true;
            if (q.name == "ns.provider.test") {
                reply.answers.push_back(a_record("ns.provider.test", "10.0.0.4"));
            } else if (q.name == "host.other.test") {
                reply.answers.push_back(a_record("host.other.test", "5.6.7.8"));
            } else {
                reply.header.rcode = Rcode::NxDomain;
            }
        };
    }

    QueryFunction query_function() {
        return [this](const std::string& ip, const std::vector<uint8_t>& bytes) -> std::optional<std::vector<uint8_t>> {
            ++queries_by_server[ip];
            const auto server = servers_.find(ip);
            if (server == servers_.end()) {
                return std::nullopt;  // unreachable server: behaves like a timeout
            }
            const Message query = decode(bytes);
            Message reply;
            reply.header.id = query.header.id;
            reply.header.qr = true;
            reply.questions = query.questions;
            server->second(query.questions[0], reply);
            return encode(reply);
        };
    }

    std::map<std::string, int> queries_by_server;

private:
    std::map<std::string, ServerLogic> servers_;
};

ResolverOptions fake_options(FakeNetwork& network, std::vector<std::string> roots = {"10.0.0.1"}) {
    ResolverOptions options;
    options.query = network.query_function();
    options.root_servers = std::move(roots);
    return options;
}

bool has_address(const ResolveResult& result, const std::string& address) {
    for (const ResourceRecord& record : result.answers) {
        if (record.type == RecordType::A && record.address == address) {
            return true;
        }
    }
    return false;
}

void test_cold_then_warm() {
    FakeNetwork network;
    Cache cache;
    Resolver resolver(&cache, fake_options(network));

    const ResolveResult cold = resolver.resolve("www.example.test", RecordType::A);
    CHECK(cold.status == ResolveStatus::Ok);
    CHECK(has_address(cold, "1.2.3.4"));
    CHECK(cold.upstream_queries == 3);  // root -> test -> example.test

    const ResolveResult warm = resolver.resolve("www.example.test", RecordType::A);
    CHECK(warm.status == ResolveStatus::Ok);
    CHECK(has_address(warm, "1.2.3.4"));
    CHECK(warm.upstream_queries == 0);
}

void test_cached_delegation_skips_root() {
    FakeNetwork network;
    Cache cache;
    Resolver resolver(&cache, fake_options(network));

    resolver.resolve("www.example.test", RecordType::A);
    const int root_queries = network.queries_by_server["10.0.0.1"];

    // A different name in the same zone goes straight to example.test's server.
    const ResolveResult result = resolver.resolve("alias.example.test", RecordType::A);
    CHECK(result.status == ResolveStatus::Ok);
    CHECK(result.upstream_queries == 1);
    CHECK(network.queries_by_server["10.0.0.1"] == root_queries);
}

void test_in_zone_cname() {
    FakeNetwork network;
    Resolver resolver(nullptr, fake_options(network));

    const ResolveResult result = resolver.resolve("alias.example.test", RecordType::A);
    CHECK(result.status == ResolveStatus::Ok);
    CHECK(result.answers.size() == 2);
    CHECK(result.answers[0].type == RecordType::CNAME && result.answers[0].target == "www.example.test");
    CHECK(has_address(result, "1.2.3.4"));
}

void test_out_of_zone_cname_and_glueless_delegation() {
    FakeNetwork network;
    Cache cache;
    Resolver resolver(&cache, fake_options(network));

    const ResolveResult result = resolver.resolve("ext.example.test", RecordType::A);
    CHECK(result.status == ResolveStatus::Ok);
    CHECK(result.answers.size() == 2);
    CHECK(result.answers[0].type == RecordType::CNAME);
    CHECK(has_address(result, "5.6.7.8"));
    CHECK(!has_address(result, "6.6.6.6"));  // out-of-bailiwick record ignored
    CHECK(cache.get("host.other.test", RecordType::A).size() == 1);
    CHECK(network.queries_by_server["10.0.0.4"] >= 2);  // ns.provider.test lookup, then the answer
}

void test_nxdomain_is_negatively_cached() {
    FakeNetwork network;
    Cache cache;
    Resolver resolver(&cache, fake_options(network));

    const ResolveResult first = resolver.resolve("missing.example.test", RecordType::A);
    CHECK(first.status == ResolveStatus::NxDomain);
    CHECK(first.soa.has_value());

    const ResolveResult second = resolver.resolve("missing.example.test", RecordType::A);
    CHECK(second.status == ResolveStatus::NxDomain);
    CHECK(second.upstream_queries == 0);
}

void test_nodata() {
    FakeNetwork network;
    Cache cache;
    Resolver resolver(&cache, fake_options(network));

    const ResolveResult result = resolver.resolve("www.example.test", RecordType::MX);
    CHECK(result.status == ResolveStatus::NoData);
    CHECK(result.answers.empty());
    CHECK(resolver.resolve("www.example.test", RecordType::MX).upstream_queries == 0);
}

void test_unreachable_server_is_skipped() {
    FakeNetwork network;
    Resolver resolver(nullptr, fake_options(network, {"10.9.9.9", "10.0.0.1"}));

    const ResolveResult result = resolver.resolve("www.example.test", RecordType::A);
    CHECK(result.status == ResolveStatus::Ok);
    CHECK(network.queries_by_server["10.9.9.9"] == 1);
}

void test_cname_loop_terminates() {
    FakeNetwork network;
    Cache cache;
    Resolver resolver(&cache, fake_options(network));

    const ResolveResult result = resolver.resolve("loop1.example.test", RecordType::A);
    CHECK(result.status == ResolveStatus::ServFail);
}

void test_no_duplicate_cache_entries() {
    FakeNetwork network;
    Cache cache;
    Resolver resolver(&cache, fake_options(network));

    resolver.resolve("www.example.test", RecordType::A);
    resolver.resolve("missing.test", RecordType::A);  // walks past the "test" delegation again
    CHECK(cache.get("test", RecordType::NS).size() == 1);
}

}  // namespace

int main() {
    test_cold_then_warm();
    test_cached_delegation_skips_root();
    test_in_zone_cname();
    test_out_of_zone_cname_and_glueless_delegation();
    test_nxdomain_is_negatively_cached();
    test_nodata();
    test_unreachable_server_is_skipped();
    test_cname_loop_terminates();
    test_no_duplicate_cache_entries();
    return dns::test::report();
}
