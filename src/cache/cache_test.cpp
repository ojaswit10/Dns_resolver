
#include "cache.h"

#include <cstdint>
#include <string>

#include "common/check.h"

int main() {
    dns::Cache cache;

    dns::ResourceRecord record;
    record.name = "example.com";
    record.type = dns::RecordType::A;
    record.klass = static_cast<uint16_t>(dns::RecordClass::IN);
    record.ttl = 60;
    record.address = "93.184.216.34";

    cache.put(record);

    auto result = cache.get("EXAMPLE.COM", dns::RecordType::A);
    CHECK(result.size() == 1);
    CHECK(result[0].address == "93.184.216.34");

    auto missing = cache.get("missing.com", dns::RecordType::A);
    CHECK(missing.empty());

    dns::ResourceRecord expired_record;
    expired_record.name = "expired.example";
    expired_record.type = dns::RecordType::A;
    expired_record.ttl = 0;
    expired_record.address = "192.0.2.1";
    cache.put(expired_record);
    CHECK(cache.get("expired.example", dns::RecordType::A).empty());

    dns::ResourceRecord soa;
    soa.name = "example.com";
    soa.type = dns::RecordType::SOA;
    soa.ttl = 300;
    soa.soa.minimum = 60;

    cache.put_negative(
        "missing.example.com", dns::RecordType::A, dns::Rcode::NxDomain, soa);

    auto negative = cache.get_negative("missing.example.com", dns::RecordType::A);
    CHECK(negative.has_value());
    CHECK(negative.value() == dns::Rcode::NxDomain);

    // NXDOMAIN applies to every record type for the same name.
    CHECK(cache.get_negative("missing.example.com", dns::RecordType::AAAA).has_value());

    // An unrelated name should not match.
    CHECK(!cache.get_negative("other.example.com", dns::RecordType::A).has_value());

    // Positive data should invalidate the matching negative entries.
    dns::ResourceRecord positive_record;
    positive_record.name = "missing.example.com";
    positive_record.type = dns::RecordType::A;
    positive_record.ttl = 60;
    positive_record.address = "192.0.2.5";
    cache.put(positive_record);
    CHECK(!cache.get_negative("missing.example.com", dns::RecordType::A).has_value());

    return dns::test::report();
}
