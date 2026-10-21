#pragma once

// RFC 1035 wire format encoder/decoder.

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

#include "dns/message.h"

namespace dns {

// Thrown by decode() for malformed packets: truncated buffers, bad label
// lengths, compression pointer loops, etc. Callers should catch it and treat
// the response as unusable rather than crash.
class ParseError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Serializes a message, compressing repeated names with pointers.
std::vector<uint8_t> encode(const Message& message);

// Parses a packet. Throws ParseError on malformed input.
Message decode(const std::vector<uint8_t>& packet);

// Builds a single-question query. rd defaults to false because an iterative
// resolver must not ask upstream servers to recurse for it.
Message make_query(uint16_t id, const std::string& name, RecordType type, bool rd = false);

}  // namespace dns
