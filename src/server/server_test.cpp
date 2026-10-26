// Server tests. Upstream DNS is faked by one "root" server (10.0.0.1) that is
// authoritative for everything, so no test needs the internet.

#include "server/server.h"

#include <atomic>
#include <thread>

#include "common/check.h"
#include "dns/codec.h"
#include "net/transport.h"

using namespace dns;

namespace {

constexpr int kBigRecordCount = 60;  // ~1 KB of A records: too big for plain 512-byte UDP

std::atomic<int> g_upstream_queries{0};

ResourceRecord a_record(const std::string& name, uint8_t last_octet) {
    ResourceRecord record;
    record.name = name;
    record.type = RecordType::A;
    record.ttl = 300;
    record.rdata = {1, 2, 3, last_octet};
    return record;
}

std::optional<std::vector<uint8_t>> fake_upstream(const std::string&, const std::vector<uint8_t>& bytes) {
    ++g_upstream_queries;
    const Message query = decode(bytes);
    const Question& question = query.questions[0];

    Message reply;
    reply.header.id = query.header.id;
    reply.header.qr = true;
    reply.header.aa = true;
    reply.questions = query.questions;

    if (question.name == "www.example.test" && question.type == RecordType::A) {
        reply.answers.push_back(a_record("www.example.test", 4));
    } else if (question.name == "big.example.test") {
        for (int i = 0; i < kBigRecordCount; ++i) {
            reply.answers.push_back(a_record("big.example.test", static_cast<uint8_t>(i)));
        }
    } else {
        reply.header.rcode = Rcode::NxDomain;
        ResourceRecord soa;
        soa.name = "example.test";
        soa.type = RecordType::SOA;
        soa.ttl = 600;
        soa.soa = SoaData{"ns1.example.test", "admin.example.test", 1, 3600, 600, 86400, 300};
        reply.authority.push_back(soa);
    }
    return encode(reply);
}

ServerOptions test_options() {
    ServerOptions options;
    options.port = 0;
    options.log_queries = false;
    options.resolver.query = fake_upstream;
    options.resolver.root_servers = {"10.0.0.1"};
    return options;
}

std::vector<uint8_t> client_query(uint16_t id, const std::string& name, bool edns = false) {
    Message query = make_query(id, name, RecordType::A, true);
    if (edns) {
        ResourceRecord opt;
        opt.type = RecordType::OPT;
        opt.klass = 4096;
        query.additional.push_back(opt);
    }
    return encode(query);
}

void test_answer() {
    Cache cache;
    Server server(cache, test_options());

    const auto reply = server.handle_packet(client_query(0x1234, "www.example.test"), "test");
    CHECK(reply.has_value());
    const Message message = decode(*reply);
    CHECK(message.header.id == 0x1234);
    CHECK(message.header.qr && message.header.ra && message.header.rd);
    CHECK(message.header.rcode == Rcode::NoError);
    CHECK(message.questions.size() == 1 && message.questions[0].name == "www.example.test");
    CHECK(message.answers.size() == 1 && message.answers[0].address == "1.2.3.4");
}

void test_second_query_comes_from_cache() {
    Cache cache;
    Server server(cache, test_options());

    server.handle_packet(client_query(1, "www.example.test"), "test");
    const int before = g_upstream_queries;
    const auto reply = server.handle_packet(client_query(2, "www.example.test"), "test");
    CHECK(g_upstream_queries == before);
    CHECK(decode(*reply).answers.size() == 1);
}

void test_nxdomain_includes_soa() {
    Cache cache;
    Server server(cache, test_options());

    const Message message = decode(*server.handle_packet(client_query(7, "missing.example.test"), "test"));
    CHECK(message.header.rcode == Rcode::NxDomain);
    CHECK(message.answers.empty());
    CHECK(message.authority.size() == 1 && message.authority[0].type == RecordType::SOA);
}

void test_truncation_and_edns() {
    Cache cache;
    Server server(cache, test_options());

    const Message plain = decode(*server.handle_packet(client_query(1, "big.example.test"), "test"));
    CHECK(plain.header.tc);
    CHECK(plain.answers.empty());

    const Message with_edns = decode(*server.handle_packet(client_query(2, "big.example.test", true), "test"));
    CHECK(!with_edns.header.tc);
    CHECK(with_edns.answers.size() == kBigRecordCount);
    CHECK(with_edns.additional.size() == 1 && with_edns.additional[0].type == RecordType::OPT);
}

void test_bad_packets() {
    Cache cache;
    Server server(cache, test_options());

    // Header claims one question that is not there: FORMERR, echoing the ID.
    const std::vector<uint8_t> garbage = {0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 5, 'a'};
    const Message formerr = decode(*server.handle_packet(garbage, "test"));
    CHECK(formerr.header.id == 0xABCD && formerr.header.rcode == Rcode::FormErr);

    CHECK(!server.handle_packet({0x01}, "test").has_value());

    Message response = make_query(3, "www.example.test", RecordType::A);
    response.header.qr = true;
    CHECK(!server.handle_packet(encode(response), "test").has_value());  // never answer a response

    Message notify = make_query(4, "example.test", RecordType::SOA);
    notify.header.opcode = 4;
    CHECK(decode(*server.handle_packet(encode(notify), "test")).header.rcode == Rcode::NotImp);
}

void test_over_real_socket_with_parallel_clients() {
    Cache cache;
    Server server(cache, test_options());
    CHECK(server.start());
    CHECK(server.port() != 0);
    std::thread loop([&server] { server.run(); });

    TransportOptions transport;
    transport.port = server.port();
    transport.timeout_ms = 3000;

    constexpr int kClients = 20;
    std::atomic<int> answered{0};
    std::vector<std::thread> clients;
    for (int i = 0; i < kClients; ++i) {
        clients.emplace_back([&, i] {
            const auto reply =
                send_udp("127.0.0.1", client_query(static_cast<uint16_t>(100 + i), "www.example.test"), transport);
            if (reply && decode(*reply).answers.size() == 1) {
                ++answered;
            }
        });
    }
    for (std::thread& client : clients) {
        client.join();
    }
    CHECK(answered == kClients);

    server.stop();
    loop.join();
}

}  // namespace

int main() {
    test_answer();
    test_second_query_comes_from_cache();
    test_nxdomain_includes_soa();
    test_truncation_and_edns();
    test_bad_packets();
    test_over_real_socket_with_parallel_clients();
    return dns::test::report();
}
