#pragma once

// Shared DNS data model (RFC 1035 section 4). Every module talks in these types.
//
// Name convention: names are stored without the trailing dot ("www.example.com"),
// and the root zone is the empty string "". Compare names with names_equal(),
// because DNS names are case-insensitive.

#include <cstdint>
#include <string>
#include <vector>

namespace dns {

// Underlying type is uint16_t, so values we do not list (e.g. 65 = HTTPS) still
// fit and survive a decode/encode round trip.
enum class RecordType : uint16_t {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    OPT = 41,
    ANY = 255,
};

enum class RecordClass : uint16_t {
    IN = 1,
};

enum class Rcode : uint8_t {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImp = 4,
    Refused = 5,
};

struct Header {
    uint16_t id = 0;
    bool qr = false;  // false = query, true = response
    uint8_t opcode = 0;
    bool aa = false;  // authoritative answer
    bool tc = false;  // truncated: retry over TCP
    bool rd = false;  // recursion desired (we send false: we resolve iteratively)
    bool ra = false;  // recursion available
    Rcode rcode = Rcode::NoError;
};

struct Question {
    std::string name;
    RecordType type = RecordType::A;
    RecordClass klass = RecordClass::IN;
};

struct SoaData {
    std::string mname;  // primary nameserver
    std::string rname;  // admin mailbox
    uint32_t serial = 0;
    uint32_t refresh = 0;
    uint32_t retry = 0;
    uint32_t expire = 0;
    uint32_t minimum = 0;  // negative-caching TTL (RFC 2308)
};

// A resource record. Which fields are meaningful depends on `type`:
//
//   A, AAAA   rdata = raw address bytes, address = text form ("93.184.216.34")
//   NS, CNAME target
//   MX        preference, target
//   SOA       soa
//   TXT       rdata = raw bytes, texts = decoded strings
//   other     rdata = raw bytes only
//
// When encoding, NS/CNAME/MX/SOA are written from the decoded fields (so names
// can be compressed). Every other type is written from `rdata`.
struct ResourceRecord {
    std::string name;
    RecordType type = RecordType::A;
    uint16_t klass = static_cast<uint16_t>(RecordClass::IN);  // raw: OPT abuses it
    uint32_t ttl = 0;
    std::vector<uint8_t> rdata;

    std::string address;
    std::string target;
    uint16_t preference = 0;
    SoaData soa;
    std::vector<std::string> texts;
};

struct Message {
    Header header;
    std::vector<Question> questions;
    std::vector<ResourceRecord> answers;
    std::vector<ResourceRecord> authority;
    std::vector<ResourceRecord> additional;
};

// "A", "AAAA", ... ; unknown types print as "TYPE65" (RFC 3597 style).
std::string to_string(RecordType type);
std::string to_string(Rcode rcode);

// Parses "A", "aaaa", "TYPE65", ... Returns false if the text is not a type.
bool parse_record_type(const std::string& text, RecordType& out);

// Lowercases and strips one trailing dot: "WWW.Example.COM." -> "www.example.com".
std::string normalize_name(const std::string& name);

bool names_equal(const std::string& a, const std::string& b);

// One-line, dig-style text for a record, e.g. "example.com 300 IN A 93.184.216.34".
std::string to_string(const ResourceRecord& record);

}  // namespace dns
