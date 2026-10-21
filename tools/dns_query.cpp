// Sends one query to one server and prints the response, like a tiny `dig`.
// Useful for checking the codec and transport against real nameservers.
//
//   dns_query <server-ip> <name> [type] [+rd]
//   dns_query 198.41.0.4 example.com A        (ask a root server; expect a referral)

#include <iostream>
#include <random>

#include "dns/codec.h"
#include "net/transport.h"

using namespace dns;

namespace {

void print_section(const char* title, const std::vector<ResourceRecord>& records) {
    if (records.empty()) {
        return;
    }
    std::cout << ";; " << title << '\n';
    for (const ResourceRecord& record : records) {
        std::cout << to_string(record) << '\n';
    }
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: dns_query <server-ip> <name> [type] [+rd]\n";
        return 2;
    }

    const std::string server = argv[1];
    const std::string name = argv[2];
    RecordType type = RecordType::A;
    bool rd = false;
    for (int i = 3; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "+rd") {
            rd = true;
        } else if (!parse_record_type(arg, type)) {
            std::cerr << "unknown record type: " << arg << '\n';
            return 2;
        }
    }

    std::random_device random;
    const uint16_t id = static_cast<uint16_t>(random());
    const auto response = send_udp(server, encode(make_query(id, name, type, rd)));
    if (!response) {
        std::cerr << "no response from " << server << '\n';
        return 1;
    }

    try {
        const Message message = decode(*response);
        const Header& h = message.header;
        std::cout << ";; status: " << to_string(h.rcode) << ", id: " << h.id << ", flags:" << (h.qr ? " qr" : "")
                  << (h.aa ? " aa" : "") << (h.tc ? " tc" : "") << (h.rd ? " rd" : "") << (h.ra ? " ra" : "")
                  << ", " << response->size() << " bytes\n";
        print_section("ANSWER", message.answers);
        print_section("AUTHORITY", message.authority);
        print_section("ADDITIONAL", message.additional);
    } catch (const ParseError& error) {
        std::cerr << "malformed response: " << error.what() << '\n';
        return 1;
    }
    return 0;
}
