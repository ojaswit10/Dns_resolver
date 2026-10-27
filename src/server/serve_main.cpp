// Runs the caching DNS server. Point nslookup, dig or the OS at it.
//
//   serve [--listen IP] [--port N] [--trace] [--quiet]
//   serve --port 5300             (no admin rights needed)
//   nslookup -port=5300 www.example.com 127.0.0.1

#include <csignal>
#include <iostream>

#include "server/server.h"

using namespace dns;

namespace {

Server* g_server = nullptr;

void handle_interrupt(int) {
    if (g_server) {
        g_server->stop();
    }
}

}  // namespace

int main(int argc, char** argv) {
    ServerOptions options;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--listen" && i + 1 < argc) {
            options.listen_ip = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            options.port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "--trace") {
            options.log_trace = true;
        } else if (arg == "--quiet") {
            options.log_queries = false;
        } else {
            std::cerr << "usage: serve [--listen IP] [--port N] [--trace] [--quiet]\n";
            return 2;
        }
    }

    Cache cache;
    Server server(cache, options);
    if (!server.start()) {
        std::cerr << "error: " << server.error() << '\n';
        if (options.port == 53) {
            std::cerr << "hint: try another port, e.g. --port 5300\n";
        }
        return 1;
    }

    g_server = &server;
    std::signal(SIGINT, handle_interrupt);
    std::cout << "DNS server listening on " << options.listen_ip << ":" << server.port() << " (Ctrl+C to stop)"
              << std::endl;

    server.run();
    std::cout << "stopped" << std::endl;
    return 0;
}
