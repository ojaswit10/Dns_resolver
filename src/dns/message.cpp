#include "dns/message.h"

#include <cctype>
#include <sstream>
#include <string>
#include <utility>

namespace dns {

namespace {

const std::pair<RecordType, const char*> kTypeNames[] = {
    {RecordType::A, "A"},
    {RecordType::NS, "NS"},
    {RecordType::CNAME, "CNAME"},
    {RecordType::SOA, "SOA"},
    {RecordType::MX, "MX"},
    {RecordType::TXT, "TXT"},
    {RecordType::AAAA, "AAAA"},
    {RecordType::OPT, "OPT"},
    {RecordType::ANY, "ANY"},
};

std::string to_upper(std::string text) {
    for (char& c : text) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return text;
}

std::string display_name(const std::string& name) {
    return name.empty() ? "." : name;
}

}  // namespace

std::string to_string(RecordType type) {
    for (const auto& [value, text] : kTypeNames) {
        if (value == type) {
            return text;
        }
    }
    return "TYPE" + std::to_string(static_cast<uint16_t>(type));
}

std::string to_string(Rcode rcode) {
    switch (rcode) {
        case Rcode::NoError:
            return "NOERROR";
        case Rcode::FormErr:
            return "FORMERR";
        case Rcode::ServFail:
            return "SERVFAIL";
        case Rcode::NxDomain:
            return "NXDOMAIN";
        case Rcode::NotImp:
            return "NOTIMP";
        case Rcode::Refused:
            return "REFUSED";
    }
    return "RCODE" + std::to_string(static_cast<int>(rcode));
}

bool parse_record_type(const std::string& text, RecordType& out) {
    const std::string upper = to_upper(text);
    for (const auto& [value, name] : kTypeNames) {
        if (upper == name) {
            out = value;
            return true;
        }
    }
    // "TYPE<n>": digits only and at most 5 of them, so stoul cannot throw or overflow.
    if (upper.compare(0, 4, "TYPE") == 0) {
        const std::string digits = upper.substr(4);
        if (!digits.empty() && digits.size() <= 5 && digits.find_first_not_of("0123456789") == std::string::npos) {
            const unsigned long number = std::stoul(digits);
            if (number <= 0xFFFF) {
                out = static_cast<RecordType>(number);
                return true;
            }
        }
    }
    return false;
}

std::string normalize_name(const std::string& name) {
    std::string result = name;
    if (!result.empty() && result.back() == '.') {
        result.pop_back();
    }
    for (char& c : result) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return result;
}

bool names_equal(const std::string& a, const std::string& b) {
    return normalize_name(a) == normalize_name(b);
}

std::string to_string(const ResourceRecord& record) {
    std::ostringstream out;
    out << display_name(record.name) << ' ' << record.ttl << ' '
        << (record.klass == static_cast<uint16_t>(RecordClass::IN) ? "IN" : "CLASS" + std::to_string(record.klass))
        << ' ' << to_string(record.type) << ' ';

    switch (record.type) {
        case RecordType::A:
        case RecordType::AAAA:
            out << record.address;
            break;
        case RecordType::NS:
        case RecordType::CNAME:
            out << display_name(record.target);
            break;
        case RecordType::MX:
            out << record.preference << ' ' << display_name(record.target);
            break;
        case RecordType::SOA:
            out << display_name(record.soa.mname) << ' ' << display_name(record.soa.rname) << ' ' << record.soa.serial
                << ' ' << record.soa.refresh << ' ' << record.soa.retry << ' ' << record.soa.expire << ' '
                << record.soa.minimum;
            break;
        case RecordType::TXT:
            for (size_t i = 0; i < record.texts.size(); ++i) {
                out << (i ? " " : "") << '"' << record.texts[i] << '"';
            }
            break;
        default:
            out << "\\# " << record.rdata.size();  // RFC 3597 unknown-type form
            break;
    }
    return out.str();
}

}  // namespace dns
