#include "dns/codec.h"

#include <cstdio>
#include <map>

namespace dns {

namespace {

constexpr size_t kHeaderSize = 12;
constexpr size_t kMaxNameLength = 255;
constexpr size_t kMaxLabelLength = 63;
constexpr size_t kMaxPointerOffset = 0x3FFF;  // 14 bits
constexpr int kMaxPointerJumps = 64;

std::vector<std::string> split_labels(const std::string& name) {
    std::vector<std::string> labels;
    const std::string trimmed = (!name.empty() && name.back() == '.') ? name.substr(0, name.size() - 1) : name;
    if (trimmed.empty()) {
        return labels;
    }
    size_t start = 0;
    while (true) {
        const size_t dot = trimmed.find('.', start);
        const std::string label = trimmed.substr(start, dot - start);
        if (label.empty() || label.size() > kMaxLabelLength) {
            throw std::invalid_argument("invalid label in name: " + name);
        }
        labels.push_back(label);
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
        // DNS wire-format names can be at most 255 bytes,
    // including each label-length byte and the terminating root byte.
    size_t wire_length = 1;

    for (const auto& label : labels) {
        wire_length += 1 + label.size();
    }

    if (wire_length > 255) {
        throw ParseError("DNS name exceeds 255 bytes");
    }
    return labels;
}

std::string join_labels(const std::vector<std::string>& labels, size_t from) {
    std::string result;
    for (size_t i = from; i < labels.size(); ++i) {
        if (!result.empty()) {
            result += '.';
        }
        result += labels[i];
    }
    return result;
}

std::string format_ipv4(const std::vector<uint8_t>& bytes) {
    char text[16];
    std::snprintf(text, sizeof(text), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);
    return text;
}

// RFC 5952 text form: lowercase hex, longest run of zero groups shown as "::".
std::string format_ipv6(const std::vector<uint8_t>& bytes) {
    uint16_t groups[8];
    for (int i = 0; i < 8; ++i) {
        groups[i] = static_cast<uint16_t>((bytes[2 * i] << 8) | bytes[2 * i + 1]);
    }

    int best_start = -1;
    int best_length = 0;
    for (int i = 0; i < 8;) {
        if (groups[i] != 0) {
            ++i;
            continue;
        }
        int j = i;
        while (j < 8 && groups[j] == 0) {
            ++j;
        }
        if (j - i > best_length && j - i >= 2) {
            best_start = i;
            best_length = j - i;
        }
        i = j;
    }

    std::string result;
    char hex[8];
    for (int i = 0; i < 8; ++i) {
        if (i == best_start) {
            result += "::";
            i += best_length - 1;
            continue;
        }
        if (!result.empty() && result.back() != ':') {
            result += ':';
        }
        std::snprintf(hex, sizeof(hex), "%x", groups[i]);
        result += hex;
    }
    return result;
}

class Writer {
public:
    void u8(uint8_t value) { buffer_.push_back(value); }

    void u16(uint16_t value) {
        buffer_.push_back(static_cast<uint8_t>(value >> 8));
        buffer_.push_back(static_cast<uint8_t>(value));
    }

    void u32(uint32_t value) {
        u16(static_cast<uint16_t>(value >> 16));
        u16(static_cast<uint16_t>(value));
    }

    void bytes(const std::vector<uint8_t>& data) { buffer_.insert(buffer_.end(), data.begin(), data.end()); }

    // Writes a name, replacing the longest already-written suffix with a pointer.
    void name(const std::string& name) {
        const std::vector<std::string> labels = split_labels(name);
        for (size_t i = 0; i < labels.size(); ++i) {
            const std::string suffix = normalize_name(join_labels(labels, i));
            const auto found = offsets_.find(suffix);
            if (found != offsets_.end()) {
                u16(static_cast<uint16_t>(0xC000 | found->second));
                return;
            }
            if (buffer_.size() <= kMaxPointerOffset) {
                offsets_[suffix] = static_cast<uint16_t>(buffer_.size());
            }
            u8(static_cast<uint8_t>(labels[i].size()));
            buffer_.insert(buffer_.end(), labels[i].begin(), labels[i].end());
        }
        u8(0);
    }

    size_t size() const { return buffer_.size(); }

    void patch_u16(size_t position, uint16_t value) {
        buffer_[position] = static_cast<uint8_t>(value >> 8);
        buffer_[position + 1] = static_cast<uint8_t>(value);
    }

    std::vector<uint8_t> take() { return std::move(buffer_); }

private:
    std::vector<uint8_t> buffer_;
    std::map<std::string, uint16_t> offsets_;  // normalized suffix -> offset
};

class Reader {
public:
    explicit Reader(const std::vector<uint8_t>& packet) : data_(packet) {}

    size_t position() const { return position_; }

    void seek(size_t position) { position_ = position; }

    uint8_t u8() {
        require(1);
        return data_[position_++];
    }

    uint16_t u16() {
        require(2);
        const uint16_t value = static_cast<uint16_t>((data_[position_] << 8) | data_[position_ + 1]);
        position_ += 2;
        return value;
    }

    uint32_t u32() {
        const uint32_t high = u16();
        return (high << 16) | u16();
    }

    std::vector<uint8_t> bytes(size_t count) {
        require(count);
        std::vector<uint8_t> result(data_.begin() + position_, data_.begin() + position_ + count);
        position_ += count;
        return result;
    }

    // Reads a possibly-compressed name. Pointers must point strictly backwards,
    // which rules out self-referencing and forward loops.
    std::string name() {
        std::string result;
        size_t cursor = position_;
        bool jumped = false;
        int jumps = 0;

        while (true) {
            if (cursor >= data_.size()) {
                throw ParseError("name runs past end of packet");
            }
            const uint8_t length = data_[cursor];

            if ((length & 0xC0) == 0xC0) {
                if (cursor + 1 >= data_.size()) {
                    throw ParseError("truncated compression pointer");
                }
                const size_t target = static_cast<size_t>(((length & 0x3F) << 8) | data_[cursor + 1]);
                if (target >= cursor) {
                    throw ParseError("compression pointer does not point backwards");
                }
                if (++jumps > kMaxPointerJumps) {
                    throw ParseError("too many compression pointers");
                }
                if (!jumped) {
                    position_ = cursor + 2;
                    jumped = true;
                }
                cursor = target;
                continue;
            }
            if (length & 0xC0) {
                throw ParseError("reserved label type");
            }
            if (length == 0) {
                if (!jumped) {
                    position_ = cursor + 1;
                }
                return result;
            }
            if (cursor + 1 + length > data_.size()) {
                throw ParseError("label runs past end of packet");
            }
            if (!result.empty()) {
                result += '.';
            }
            result.append(reinterpret_cast<const char*>(&data_[cursor + 1]), length);
            if (result.size() > kMaxNameLength) {
                throw ParseError("name longer than 255 bytes");
            }
            cursor += 1 + length;
        }
    }

private:
    void require(size_t count) const {
        if (position_ + count > data_.size()) {
            throw ParseError("unexpected end of packet");
        }
    }

    const std::vector<uint8_t>& data_;
    size_t position_ = 0;
};

void write_record(Writer& writer, const ResourceRecord& record) {
    writer.name(record.name);
    writer.u16(static_cast<uint16_t>(record.type));
    writer.u16(record.klass);
    writer.u32(record.ttl);

    const size_t length_position = writer.size();
    writer.u16(0);  // RDLENGTH, patched below
    const size_t rdata_start = writer.size();

    switch (record.type) {
        case RecordType::NS:
        case RecordType::CNAME:
            writer.name(record.target);
            break;
        case RecordType::MX:
            writer.u16(record.preference);
            writer.name(record.target);
            break;
        case RecordType::SOA:
            writer.name(record.soa.mname);
            writer.name(record.soa.rname);
            writer.u32(record.soa.serial);
            writer.u32(record.soa.refresh);
            writer.u32(record.soa.retry);
            writer.u32(record.soa.expire);
            writer.u32(record.soa.minimum);
            break;
        default:
            writer.bytes(record.rdata);
            break;
    }

    size_t rdata_length = writer.size() - rdata_start;

    if (rdata_length > 65535) {
        throw ParseError("RDATA exceeds maximum length");
    }

    writer.patch_u16(length_position, static_cast<uint16_t>(rdata_length));
}

ResourceRecord read_record(Reader& reader) {
    ResourceRecord record;
    record.name = reader.name();
    record.type = static_cast<RecordType>(reader.u16());
    record.klass = reader.u16();
    record.ttl = reader.u32();
    const uint16_t rdlength = reader.u16();

    const size_t rdata_start = reader.position();
    record.rdata = reader.bytes(rdlength);
    const size_t rdata_end = reader.position();

    // Names inside RDATA may point anywhere earlier in the packet, so they are
    // decoded from the full packet with a second reader positioned at RDATA.
    Reader inner = reader;
    auto seek_rdata = [&]() { inner.seek(rdata_start); };

    switch (record.type) {
        case RecordType::A:
            if (rdlength != 4) {
                throw ParseError("A record with RDLENGTH != 4");
            }
            record.address = format_ipv4(record.rdata);
            break;
        case RecordType::AAAA:
            if (rdlength != 16) {
                throw ParseError("AAAA record with RDLENGTH != 16");
            }
            record.address = format_ipv6(record.rdata);
            break;
        case RecordType::NS:
        case RecordType::CNAME:
            seek_rdata();
            record.target = inner.name();
            break;
        case RecordType::MX:
            seek_rdata();
            record.preference = inner.u16();
            record.target = inner.name();
            break;
        case RecordType::SOA:
            seek_rdata();
            record.soa.mname = inner.name();
            record.soa.rname = inner.name();
            record.soa.serial = inner.u32();
            record.soa.refresh = inner.u32();
            record.soa.retry = inner.u32();
            record.soa.expire = inner.u32();
            record.soa.minimum = inner.u32();
            break;
        case RecordType::TXT: {
            size_t i = 0;
            while (i < record.rdata.size()) {
                const size_t length = record.rdata[i];
                if (i + 1 + length > record.rdata.size()) {
                    throw ParseError("TXT string runs past RDATA");
                }
                record.texts.emplace_back(reinterpret_cast<const char*>(&record.rdata[i + 1]), length);
                i += 1 + length;
            }
            break;
        }
        default:
            break;
    }

    if (inner.position() > rdata_end) {
        throw ParseError("RDATA longer than RDLENGTH");
    }

    if ((record.type == RecordType::NS ||
         record.type == RecordType::CNAME ||
        record.type == RecordType::MX ||
        record.type == RecordType::SOA) &&
        inner.position() != rdata_end) {
        throw ParseError("Unexpected trailing bytes in structured RDATA");
    }
    return record;
}

}  // namespace

std::vector<uint8_t> encode(const Message& message) {
    Writer writer;
    const Header& h = message.header;

    if (message.questions.size() > 65535 ||
    message.answers.size() > 65535 ||
    message.authority.size() > 65535 ||
    message.additional.size() > 65535) {
    throw ParseError("DNS section count exceeds maximum");
    }

    writer.u16(h.id);
    writer.u8(static_cast<uint8_t>((h.qr << 7) | ((h.opcode & 0x0F) << 3) | (h.aa << 2) | (h.tc << 1) | h.rd));
    writer.u8(static_cast<uint8_t>((h.ra << 7) | (static_cast<uint8_t>(h.rcode) & 0x0F)));
    writer.u16(static_cast<uint16_t>(message.questions.size()));
    writer.u16(static_cast<uint16_t>(message.answers.size()));
    writer.u16(static_cast<uint16_t>(message.authority.size()));
    writer.u16(static_cast<uint16_t>(message.additional.size()));

    for (const Question& question : message.questions) {
        writer.name(question.name);
        writer.u16(static_cast<uint16_t>(question.type));
        writer.u16(static_cast<uint16_t>(question.klass));
    }
    for (const auto* section : {&message.answers, &message.authority, &message.additional}) {
        for (const ResourceRecord& record : *section) {
            write_record(writer, record);
        }
    }
    return writer.take();
}

Message decode(const std::vector<uint8_t>& packet) {
    if (packet.size() < kHeaderSize) {
        throw ParseError("packet shorter than DNS header");
    }

    Reader reader(packet);
    Message message;
    Header& h = message.header;

    h.id = reader.u16();
    const uint8_t flags_high = reader.u8();
    const uint8_t flags_low = reader.u8();
    h.qr = flags_high & 0x80;
    h.opcode = (flags_high >> 3) & 0x0F;
    h.aa = flags_high & 0x04;
    h.tc = flags_high & 0x02;
    h.rd = flags_high & 0x01;
    h.ra = flags_low & 0x80;
    h.rcode = static_cast<Rcode>(flags_low & 0x0F);

    const uint16_t question_count = reader.u16();
    const uint16_t answer_count = reader.u16();
    const uint16_t authority_count = reader.u16();
    const uint16_t additional_count = reader.u16();

    for (uint16_t i = 0; i < question_count; ++i) {
        Question question;
        question.name = reader.name();
        question.type = static_cast<RecordType>(reader.u16());
        question.klass = static_cast<RecordClass>(reader.u16());
        message.questions.push_back(question);
    }
    for (uint16_t i = 0; i < answer_count; ++i) {
        message.answers.push_back(read_record(reader));
    }
    for (uint16_t i = 0; i < authority_count; ++i) {
        message.authority.push_back(read_record(reader));
    }
    for (uint16_t i = 0; i < additional_count; ++i) {
        message.additional.push_back(read_record(reader));
    }
    if (reader.position() != packet.size()) {
        throw ParseError("Unexpected trailing bytes in DNS packet");
    }
    return message;
}

Message make_query(uint16_t id, const std::string& name, RecordType type, bool rd) {
    Message message;
    message.header.id = id;
    message.header.rd = rd;
    message.questions.push_back(Question{name, type, RecordClass::IN});
    return message;
}

}  // namespace dns
