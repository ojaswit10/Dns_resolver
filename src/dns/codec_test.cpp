#include "dns/codec.h"

#include "common/check.h"

using namespace dns;

namespace {

ResourceRecord make_record(const std::string& name, RecordType type, uint32_t ttl) {
    ResourceRecord record;
    record.name = name;
    record.type = type;
    record.ttl = ttl;
    return record;
}

void test_query_bytes() {
    const std::vector<uint8_t> bytes = encode(make_query(0x1234, "example.com", RecordType::A));
    const std::vector<uint8_t> expected = {
        0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // header
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,                // name
        0x00, 0x01, 0x00, 0x01,                                                  // A, IN
    };
    CHECK(bytes == expected);
}

void test_header_flags() {
    Message message = make_query(7, "example.com", RecordType::A, true);
    message.header.qr = true;
    message.header.aa = true;
    message.header.tc = true;
    message.header.ra = true;
    message.header.rcode = Rcode::NxDomain;

    const Header h = decode(encode(message)).header;
    CHECK(h.id == 7);
    CHECK(h.qr && h.aa && h.tc && h.rd && h.ra);
    CHECK(h.rcode == Rcode::NxDomain);
}

void test_compression_pointer_written() {
    Message message = make_query(1, "example.com", RecordType::A);
    ResourceRecord answer = make_record("example.com", RecordType::A, 300);
    answer.rdata = {93, 184, 216, 34};
    message.answers.push_back(answer);

    const std::vector<uint8_t> bytes = encode(message);
    // The question name starts at offset 12, so the answer name must be the pointer C0 0C.
    const size_t answer_offset = 12 + 13 + 4;
    CHECK(bytes.size() > answer_offset + 1);
    CHECK(bytes[answer_offset] == 0xC0 && bytes[answer_offset + 1] == 0x0C);
}

void test_round_trip_all_types() {
    Message message = make_query(42, "example.com", RecordType::ANY);
    message.header.qr = true;

    ResourceRecord a = make_record("example.com", RecordType::A, 300);
    a.rdata = {93, 184, 216, 34};
    ResourceRecord aaaa = make_record("example.com", RecordType::AAAA, 300);
    aaaa.rdata = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    ResourceRecord cname = make_record("www.example.com", RecordType::CNAME, 60);
    cname.target = "example.com";
    ResourceRecord mx = make_record("example.com", RecordType::MX, 3600);
    mx.preference = 10;
    mx.target = "mail.example.com";
    ResourceRecord txt = make_record("example.com", RecordType::TXT, 60);
    txt.rdata = {5, 'h', 'e', 'l', 'l', 'o', 2, 'h', 'i'};
    ResourceRecord unknown = make_record("example.com", static_cast<RecordType>(65), 60);
    unknown.rdata = {1, 2, 3};
    message.answers = {a, aaaa, cname, mx, txt, unknown};

    ResourceRecord ns = make_record("example.com", RecordType::NS, 86400);
    ns.target = "a.iana-servers.net";
    ResourceRecord soa = make_record("example.com", RecordType::SOA, 3600);
    soa.soa = SoaData{"ns.icann.org", "noc.dns.icann.org", 2024, 7200, 3600, 1209600, 3600};
    message.authority = {ns, soa};

    ResourceRecord glue = make_record("a.iana-servers.net", RecordType::A, 86400);
    glue.rdata = {199, 43, 135, 53};
    message.additional = {glue};

    const Message decoded = decode(encode(message));
    CHECK(decoded.questions.size() == 1 && decoded.questions[0].name == "example.com");
    CHECK(decoded.answers.size() == 6);
    CHECK(decoded.answers[0].address == "93.184.216.34");
    CHECK(decoded.answers[1].address == "2001:db8::1");
    CHECK(decoded.answers[2].target == "example.com");
    CHECK(decoded.answers[3].preference == 10 && decoded.answers[3].target == "mail.example.com");
    CHECK(decoded.answers[4].texts.size() == 2 && decoded.answers[4].texts[0] == "hello");
    CHECK(static_cast<uint16_t>(decoded.answers[5].type) == 65 && decoded.answers[5].rdata.size() == 3);
    CHECK(decoded.authority[0].target == "a.iana-servers.net");
    CHECK(decoded.authority[1].soa.rname == "noc.dns.icann.org" && decoded.authority[1].soa.minimum == 3600);
    CHECK(decoded.additional[0].address == "199.43.135.53" && decoded.additional[0].ttl == 86400);
}

void test_root_name() {
    const Message decoded = decode(encode(make_query(1, "", RecordType::NS)));
    CHECK(decoded.questions[0].name.empty());
}

void test_malformed_packets() {
    const std::vector<uint8_t> header_only_question = {0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0};

    CHECK_THROWS(decode({0x12, 0x34, 0x00}), ParseError);  // shorter than header

    std::vector<uint8_t> self_pointer = header_only_question;
    self_pointer.insert(self_pointer.end(), {0xC0, 0x0C, 0, 1, 0, 1});  // points at itself
    CHECK_THROWS(decode(self_pointer), ParseError);

    std::vector<uint8_t> forward_pointer = header_only_question;
    forward_pointer.insert(forward_pointer.end(), {0xC0, 0x20, 0, 1, 0, 1});
    CHECK_THROWS(decode(forward_pointer), ParseError);

    std::vector<uint8_t> long_label = header_only_question;
    long_label.insert(long_label.end(), {10, 'a', 'b'});  // label claims 10 bytes, has 2
    CHECK_THROWS(decode(long_label), ParseError);

    Message bad_a = make_query(1, "example.com", RecordType::A);
    ResourceRecord short_a = make_record("example.com", RecordType::A, 1);
    short_a.rdata = {1, 2, 3};
    bad_a.answers.push_back(short_a);
    CHECK_THROWS(decode(encode(bad_a)), ParseError);

    std::vector<uint8_t> truncated = encode(make_query(1, "example.com", RecordType::A));
    truncated[7] = 1;  // claim one answer that is not there
    CHECK_THROWS(decode(truncated), ParseError);

        // A compression pointer with only its first byte present.
    CHECK_THROWS(
        decode(std::vector<uint8_t>{
            0x00, 0x01, // ID
            0x00, 0x00, // Flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            0xC0        // Incomplete compression pointer
        }),
        ParseError
    );

        // TXT record declares 5 bytes but contains only 2.
    CHECK_THROWS(
        decode(std::vector<uint8_t>{
            0x00, 0x01, // ID
            0x81, 0x80, // Flags
            0x00, 0x00, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT

            0x00,       // Root name
            0x00, 0x10, // TXT type
            0x00, 0x01, // IN class
            0x00, 0x00, 0x00, 0x3C, // TTL
            0x00, 0x03, // RDLENGTH = 3
            0x05,       // String length = 5
            0x41, 0x42  // Only 2 bytes of string data
        }),
        ParseError
    );
        // CNAME RDATA contains a valid root name followed by an extra byte.
    CHECK_THROWS(
        decode(std::vector<uint8_t>{
            0x00, 0x01, // ID
            0x81, 0x80, // Flags
            0x00, 0x00, // QDCOUNT
            0x00, 0x01, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT

            0x00,       // Root owner name
            0x00, 0x05, // CNAME type
            0x00, 0x01, // IN class
            0x00, 0x00, 0x00, 0x3C, // TTL
            0x00, 0x02, // RDLENGTH = 2
            0x00,       // Valid root target name
            0xAA        // Unexpected extra byte
        }),
        ParseError
    );
        // Packet contains an unexpected byte after all declared sections.
    std::vector<uint8_t> packet = encode(
        make_query(1, "example.com", RecordType::A)
    );

    packet.push_back(0xAA);

    CHECK_THROWS(decode(packet), ParseError);
}

void test_helpers() {
    CHECK(names_equal("WWW.Example.COM.", "www.example.com"));
    CHECK(to_string(RecordType::AAAA) == "AAAA");
    CHECK(to_string(static_cast<RecordType>(65)) == "TYPE65");
    RecordType type{};
    CHECK(parse_record_type("mx", type) && type == RecordType::MX);
    CHECK(parse_record_type("TYPE65", type) && static_cast<uint16_t>(type) == 65);
    CHECK(!parse_record_type("nope", type));
}

void test_invalid_name_length() {
    // Each label is valid (63 bytes), but the complete DNS name
    // exceeds the 255-byte wire-format limit.
    std::string long_name =
        std::string(63, 'a') + "." +
        std::string(63, 'b') + "." +
        std::string(63, 'c') + "." +
        std::string(63, 'd');

    CHECK_THROWS(
        encode(make_query(1, long_name, RecordType::A)),
        ParseError
    );
}

}  // namespace

void test_oversized_rdata() {
    ResourceRecord record = make_record("example.com", RecordType::TXT, 60);
    record.rdata = std::vector<uint8_t>(65536, 0x41);

    Message message = make_query(1, "example.com", RecordType::A);
    message.answers.push_back(record);

    CHECK_THROWS(encode(message), ParseError);
}

void test_oversized_section_count() {
    Message message = make_query(1, "example.com", RecordType::A);

    message.questions.resize(65536);

    CHECK_THROWS(encode(message), ParseError);
}

int main() {
    test_query_bytes();
    test_header_flags();
    test_compression_pointer_written();
    test_round_trip_all_types();
    test_root_name();
    test_malformed_packets();
    test_helpers();
    test_invalid_name_length();
    test_oversized_rdata();
    test_oversized_section_count();
    return dns::test::report();
}
