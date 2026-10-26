// Resolves a name iteratively from the root servers and prints every step.
//
//   resolve <name> [type] [--repeat N] [--quiet] [--no-cache]
//   resolve www.example.com A --repeat 2    (cold run, then a warm run from cache)

#include <algorithm>
#include <chrono>
#include <iostream>

#include "resolver/resolver.h"

using namespace dns;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: resolve <name> [type] [--repeat N] [--quiet] [--no-cache]\n";
        return 2;
    }

    const std::string name = argv[1];
    RecordType type = RecordType::A;
    int repeat = 1;
    bool quiet = false;
    bool use_cache = true;
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--repeat" && i + 1 < argc) {
            repeat = std::max(1, std::stoi(argv[++i]));
        } else if (arg == "--quiet") {
            quiet = true;
        } else if (arg == "--no-cache") {
            use_cache = false;
        } else if (!parse_record_type(arg, type)) {
            std::cerr << "unknown argument: " << arg << '\n';
            return 2;
        }
    }

    Cache cache;
    Resolver resolver(use_cache ? &cache : nullptr);
    ResolveResult result;

    for (int run = 1; run <= repeat; ++run) {
        const auto start = std::chrono::steady_clock::now();
        result = resolver.resolve(name, type);
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

        std::cout << ";; run " << run << ": " << to_string(result.status) << ", " << result.upstream_queries
                  << " upstream queries, " << elapsed << " ms\n";
        if (!quiet) {
            for (const std::string& line : result.trace) {
                std::cout << ";;   " << line << '\n';
            }
        }
    }

    for (const ResourceRecord& record : result.answers) {
        std::cout << to_string(record) << '\n';
    }
    if (result.soa) {
        std::cout << ";; SOA " << to_string(*result.soa) << '\n';
    }
    return result.status == ResolveStatus::ServFail ? 1 : 0;
}
