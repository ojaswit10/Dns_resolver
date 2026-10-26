#include "server/server.h"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <thread>

#include "dns/codec.h"

// <windows.h> defines IN as an empty macro, which breaks RecordClass::IN.
#ifdef IN
#undef IN
#endif

namespace dns {

namespace {

constexpr size_t kMaxPlainUdp = 512;      // RFC 1035 limit without EDNS
constexpr size_t kMaxEdnsPayload = 1232;  // safe size that avoids IP fragmentation
constexpr size_t kReceiveBuffer = 4096;

std::string display(const std::string& name) {
    return name.empty() ? "." : name;
}

const ResourceRecord* find_opt(const Message& message) {
    for (const ResourceRecord& record : message.additional) {
        if (record.type == RecordType::OPT) {
            return &record;
        }
    }
    return nullptr;
}

// A reply that echoes the query's ID and question with the given error code.
std::vector<uint8_t> error_reply(const Message& query, Rcode rcode) {
    Message reply;
    reply.header.id = query.header.id;
    reply.header.qr = true;
    reply.header.opcode = query.header.opcode;
    reply.header.rd = query.header.rd;
    reply.header.ra = true;
    reply.header.rcode = rcode;
    reply.questions = query.questions;
    return encode(reply);
}

}  // namespace

std::vector<uint8_t> build_response(const Message& query, const ResolveResult& result, size_t max_size) {
    Message reply;
    reply.header.id = query.header.id;
    reply.header.qr = true;
    reply.header.opcode = query.header.opcode;
    reply.header.rd = query.header.rd;
    reply.header.ra = true;
    reply.questions = query.questions;

    // Negative answers keep any CNAME chain that led to them (RFC 2308 section 2).
    reply.answers = result.answers;
    switch (result.status) {
        case ResolveStatus::Ok:
        case ResolveStatus::NoData: break;
        case ResolveStatus::NxDomain: reply.header.rcode = Rcode::NxDomain; break;
        case ResolveStatus::ServFail:
            reply.header.rcode = Rcode::ServFail;
            reply.answers.clear();
            break;
    }
    // The SOA tells the client how long it may cache the negative answer.
    if (result.soa && result.status != ResolveStatus::Ok) {
        reply.authority.push_back(*result.soa);
    }

    // Clients that sent EDNS get an OPT record back, announcing our UDP size.
    if (find_opt(query)) {
        ResourceRecord opt;
        opt.type = RecordType::OPT;
        opt.klass = static_cast<uint16_t>(kMaxEdnsPayload);
        reply.additional.push_back(opt);
    }

    std::vector<uint8_t> bytes = encode(reply);
    if (bytes.size() > max_size) {
        // Too big for this client over UDP: send an empty, truncated reply so it retries over TCP.
        reply.answers.clear();
        reply.authority.clear();
        reply.header.tc = true;
        bytes = encode(reply);
    }
    return bytes;
}

Server::Server(Cache& cache, ServerOptions options) : cache_(cache), options_(std::move(options)) {}

Server::~Server() {
    stop();
    if (socket_ != net::kInvalidSocket) {
        net::close_socket(socket_);
    }
}

bool Server::start() {
    if (!net::init_sockets()) {
        error_ = "could not initialise sockets";
        return false;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(options_.port);
    if (inet_pton(AF_INET, options_.listen_ip.c_str(), &address.sin_addr) != 1) {
        error_ = "invalid listen address " + options_.listen_ip;
        return false;
    }

    socket_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_ == net::kInvalidSocket) {
        error_ = "could not create socket";
        return false;
    }
    if (bind(socket_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        error_ = "could not bind " + options_.listen_ip + ":" + std::to_string(options_.port) +
                 " (port already in use, or needs administrator/root rights)";
        net::close_socket(socket_);
        socket_ = net::kInvalidSocket;
        return false;
    }

    sockaddr_in bound{};
    net::SockLen length = sizeof(bound);
    getsockname(socket_, reinterpret_cast<sockaddr*>(&bound), &length);
    port_ = ntohs(bound.sin_port);
    return true;
}

void Server::run() {
    std::vector<uint8_t> buffer(kReceiveBuffer);

    while (!stopping_) {
        if (!net::wait_readable(socket_, 200)) {
            continue;  // timeout: re-check stopping_
        }
        sockaddr_in client{};
        net::SockLen length = sizeof(client);
        const auto received = recvfrom(socket_, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()),
                                       0, reinterpret_cast<sockaddr*>(&client), &length);
        if (received <= 0) {
            continue;  // includes Windows reporting an ICMP error from an earlier reply
        }

        bool accepted = false;
        {
            std::lock_guard<std::mutex> lock(in_flight_mutex_);
            if (in_flight_ < options_.max_in_flight) {
                ++in_flight_;
                accepted = true;
            }
        }
        if (!accepted) {
            print("busy: dropping a query (the client will retry)");
            continue;
        }

        // Each query is resolved on its own thread, so one slow lookup doesn't block the rest.
        std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + received);
        std::thread(&Server::serve_one, this, std::move(packet), client).detach();
    }

    std::unique_lock<std::mutex> lock(in_flight_mutex_);
    in_flight_done_.wait(lock, [this] { return in_flight_ == 0; });
}

void Server::stop() {
    stopping_ = true;
}

std::optional<std::vector<uint8_t>> Server::handle_packet(const std::vector<uint8_t>& packet,
                                                          const std::string& client) {
    Message query;
    try {
        query = decode(packet);
    } catch (const ParseError&) {
        if (packet.size() < 2) {
            return std::nullopt;
        }
        Message unreadable;
        unreadable.header.id = static_cast<uint16_t>((packet[0] << 8) | packet[1]);
        return error_reply(unreadable, Rcode::FormErr);
    }

    if (query.header.qr) {
        return std::nullopt;  // a response, not a query: never answer those
    }
    if (query.header.opcode != 0) {
        return error_reply(query, Rcode::NotImp);
    }
    if (query.questions.size() != 1) {
        return error_reply(query, Rcode::FormErr);
    }
    const Question& question = query.questions[0];
    if (question.klass != RecordClass::IN) {
        return error_reply(query, Rcode::NotImp);
    }

    ResolverOptions resolver_options = options_.resolver;
    resolver_options.cache_mutex = &cache_mutex_;
    Resolver resolver(&cache_, resolver_options);

    const auto start = std::chrono::steady_clock::now();
    const ResolveResult result = resolver.resolve(question.name, question.type);
    const auto elapsed =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

    size_t max_size = kMaxPlainUdp;
    if (const ResourceRecord* opt = find_opt(query)) {
        max_size = std::clamp<size_t>(opt->klass, kMaxPlainUdp, kMaxEdnsPayload);
    }

    if (options_.log_queries) {
        print(client + "  " + display(question.name) + " " + to_string(question.type) + " -> " +
              to_string(result.status) + ", " + std::to_string(result.answers.size()) + " answer(s), " +
              std::to_string(result.upstream_queries) + " upstream, " + std::to_string(elapsed) + " ms");
    }
    if (options_.log_trace) {
        for (const std::string& line : result.trace) {
            print("    " + line);
        }
    }
    return build_response(query, result, max_size);
}

void Server::serve_one(std::vector<uint8_t> packet, sockaddr_in client) {
    char ip[INET_ADDRSTRLEN] = "?";
    inet_ntop(AF_INET, &client.sin_addr, ip, sizeof(ip));
    const std::string who = std::string(ip) + ":" + std::to_string(ntohs(client.sin_port));

    try {
        const std::optional<std::vector<uint8_t>> reply = handle_packet(packet, who);
        if (reply) {
            std::lock_guard<std::mutex> lock(send_mutex_);
            sendto(socket_, reinterpret_cast<const char*>(reply->data()), static_cast<int>(reply->size()), 0,
                   reinterpret_cast<const sockaddr*>(&client), sizeof(client));
        }
    } catch (const std::exception& error) {
        print("error answering " + who + ": " + error.what());
    }

    {
        std::lock_guard<std::mutex> lock(in_flight_mutex_);
        --in_flight_;
    }
    in_flight_done_.notify_all();
}

void Server::print(const std::string& line) {
    std::lock_guard<std::mutex> lock(print_mutex_);
    std::cout << line << std::endl;
}

}  // namespace dns
