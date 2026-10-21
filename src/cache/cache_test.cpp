#include "cache.h"

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

    auto result = cache.get("example.com", dns::RecordType::A);
    CHECK(result.size() == 1);
    CHECK(result[0].address == "93.184.216.34");

    auto missing = cache.get("missing.com", dns::RecordType::A);
    CHECK(missing.empty());

    dns::ResourceRecord expired_record;
    expired_record.name = "expired.example";
    expired_record.type = dns::RecordType::A;
    expired_record.klass = static_cast<uint16_t>(dns::RecordClass::IN);
    expired_record.ttl = 0;
    expired_record.address = "192.0.2.1";

    cache.put(expired_record);

    auto expired = cache.get("expired.example", dns::RecordType::A);
    CHECK(expired.empty());

    return 0;
}
