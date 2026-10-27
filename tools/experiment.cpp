// Tests the project's claim: a warm-cache iterative resolver answers repeated
// queries faster and with far fewer upstream queries than a cold one, without
// changing the answers.
//
// Replays a fixed list of names in three modes and writes one CSV row per lookup:
//   no-cache  every lookup walks root -> TLD -> authoritative (what `dig +trace` does)
//   cold      one cache, starting empty (later names reuse delegations from earlier ones)
//   warm      the same cache, replaying the same list again
//
//   experiment <trace-file> [--mix NAME] [--trials N] [--out FILE] [--reference IP]
//   experiment experiment/traces/popular.txt --mix popular --trials 3 --out experiment/results/popular.csv

#include <algorithm>
#include <chrono>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <sstream>

#include "dns/codec.h"
#include "net/transport.h"
#include "resolver/resolver.h"

using namespace dns;

namespace {

struct Lookup {
    std::string name;
    RecordType type = RecordType::A;
};

struct Row {
    std::string mode;
    int trial = 0;
    const Lookup* lookup = nullptr;
    ResolveResult result;
    double latency_ms = 0;
};

// What a public resolver said about a name, used as the correctness reference.
struct Reference {
    bool answered = false;
    std::string status;
    std::set<std::string> answers;
};

std::vector<Lookup> read_trace(const std::string& path) {
    std::ifstream file(path);
    std::vector<Lookup> lookups;
    std::string line;
    while (std::getline(file, line)) {
        std::istringstream words(line);
        Lookup lookup;
        std::string type;
        if (!(words >> lookup.name) || lookup.name[0] == '#') {
            continue;
        }
        if (words >> type && !parse_record_type(type, lookup.type)) {
            std::cerr << "skipping line with unknown type: " << line << '\n';
            continue;
        }
        lookups.push_back(lookup);
    }
    return lookups;
}

// Answer data without TTLs, so two answers can be compared.
std::set<std::string> answer_set(const std::vector<ResourceRecord>& records) {
    std::set<std::string> result;
    for (const ResourceRecord& record : records) {
        std::string data = record.address.empty() ? normalize_name(record.target) : record.address;
        if (record.type == RecordType::MX) {
            data = std::to_string(record.preference) + " " + data;
        } else if (record.type == RecordType::TXT) {
            for (const std::string& text : record.texts) {
                data += text;
            }
        }
        result.insert(normalize_name(record.name) + " " + to_string(record.type) + " " + data);
    }
    return result;
}

Reference ask_reference(const std::string& server, const Lookup& lookup) {
    Reference reference;
    std::random_device random;
    const auto reply =
        send_query(server, encode(make_query(static_cast<uint16_t>(random()), lookup.name, lookup.type, /*rd=*/true)));
    if (!reply) {
        return reference;
    }
    try {
        const Message message = decode(*reply);
        reference.answered = true;
        reference.answers = answer_set(message.answers);
        if (message.header.rcode == Rcode::NxDomain) {
            reference.status = "NXDOMAIN";
        } else if (message.header.rcode != Rcode::NoError) {
            reference.status = "SERVFAIL";
        } else {
            bool has_type = false;
            for (const ResourceRecord& record : message.answers) {
                has_type = has_type || record.type == lookup.type;
            }
            reference.status = has_type ? "NOERROR" : "NODATA";
        }
    } catch (const ParseError&) {
        reference.answered = false;
    }
    return reference;
}

// Same outcome as the reference. NXDOMAIN and NODATA count as the same "no records"
// outcome: some providers (e.g. Cloudflare) answer NXDOMAIN to plain queries but
// NODATA to DNSSEC-validating resolvers like 1.1.1.1 ("compact denial of existence").
bool same_outcome(const ResolveResult& result, const Reference& reference) {
    if (!reference.answered) {
        return false;
    }
    const bool our_negative = result.status == ResolveStatus::NxDomain || result.status == ResolveStatus::NoData;
    const bool their_negative = reference.status == "NXDOMAIN" || reference.status == "NODATA";
    if (our_negative || their_negative) {
        return our_negative && their_negative;
    }
    return to_string(result.status) == reference.status;
}

// For names both sides answered: at least one record in common. Exact equality is too
// strict, because CDNs hand different resolvers different addresses.
std::optional<bool> shares_record(const ResolveResult& result, const Reference& reference) {
    if (result.status != ResolveStatus::Ok || reference.status != "NOERROR") {
        return std::nullopt;
    }
    const std::set<std::string> ours = answer_set(result.answers);
    return std::any_of(ours.begin(), ours.end(), [&](const std::string& a) { return reference.answers.count(a) > 0; });
}

double percentile(std::vector<double> values, double fraction) {
    if (values.empty()) {
        return 0;
    }
    std::sort(values.begin(), values.end());
    const size_t rank = static_cast<size_t>(std::ceil(fraction * values.size()));
    return values[std::min(values.size() - 1, rank == 0 ? 0 : rank - 1)];
}

std::vector<Row> run_mode(const std::string& mode, int trial, const std::vector<Lookup>& lookups, Cache* cache) {
    std::vector<Row> rows;
    for (const Lookup& lookup : lookups) {
        // no-cache gets a brand-new resolver with no cache for every name.
        Resolver resolver(cache);
        const auto start = std::chrono::steady_clock::now();
        Row row;
        row.mode = mode;
        row.trial = trial;
        row.lookup = &lookup;
        row.result = resolver.resolve(lookup.name, lookup.type);
        row.latency_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        rows.push_back(std::move(row));
        std::cerr << '.' << std::flush;
    }
    return rows;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: experiment <trace-file> [--mix NAME] [--trials N] [--out FILE] [--reference IP]\n";
        return 2;
    }

    const std::string trace_path = argv[1];
    std::string mix = "trace";
    std::string out_path = "experiment.csv";
    std::string reference_server = "1.1.1.1";
    int trials = 3;
    for (int i = 2; i + 1 < argc; i += 2) {
        const std::string flag = argv[i];
        const std::string value = argv[i + 1];
        if (flag == "--mix") {
            mix = value;
        } else if (flag == "--trials") {
            trials = std::max(1, std::stoi(value));
        } else if (flag == "--out") {
            out_path = value;
        } else if (flag == "--reference") {
            reference_server = value;
        } else {
            std::cerr << "unknown option: " << flag << '\n';
            return 2;
        }
    }

    const std::vector<Lookup> lookups = read_trace(trace_path);
    if (lookups.empty()) {
        std::cerr << "no lookups in " << trace_path << '\n';
        return 1;
    }

    std::cerr << "asking reference resolver " << reference_server << " ";
    std::map<const Lookup*, Reference> references;
    for (const Lookup& lookup : lookups) {
        references[&lookup] = ask_reference(reference_server, lookup);
        std::cerr << '.' << std::flush;
    }
    std::cerr << '\n';

    std::vector<Row> rows;
    for (int trial = 1; trial <= trials; ++trial) {
        std::cerr << "trial " << trial << "/" << trials << " ";
        std::vector<Row> no_cache = run_mode("no-cache", trial, lookups, nullptr);
        Cache cache;
        std::vector<Row> cold = run_mode("cold", trial, lookups, &cache);
        std::vector<Row> warm = run_mode("warm", trial, lookups, &cache);
        std::cerr << '\n';
        for (auto* part : {&no_cache, &cold, &warm}) {
            rows.insert(rows.end(), part->begin(), part->end());
        }
    }

    // Warm answers are checked against the cold answers of the same trial.
    std::map<std::pair<int, const Lookup*>, const Row*> cold_rows;
    for (const Row& row : rows) {
        if (row.mode == "cold") {
            cold_rows[{row.trial, row.lookup}] = &row;
        }
    }

    std::ofstream csv(out_path);
    csv << "mix,trial,mode,name,type,status,answers,upstream_queries,latency_ms,cache_hit,matches_cold,"
           "reference_status,same_outcome_as_reference,shares_record_with_reference\n";
    for (const Row& row : rows) {
        std::string matches_cold;
        if (row.mode == "warm") {
            const Row* cold = cold_rows.at({row.trial, row.lookup});
            const bool same = row.result.status == cold->result.status &&
                              answer_set(row.result.answers) == answer_set(cold->result.answers);
            matches_cold = same ? "1" : "0";
        }
        const Reference& reference = references.at(row.lookup);
        const std::optional<bool> shares = shares_record(row.result, reference);
        csv << mix << ',' << row.trial << ',' << row.mode << ',' << row.lookup->name << ','
            << to_string(row.lookup->type) << ',' << to_string(row.result.status) << ',' << row.result.answers.size()
            << ',' << row.result.upstream_queries << ',' << std::fixed << std::setprecision(2) << row.latency_ms << ','
            << (row.result.upstream_queries == 0 ? 1 : 0) << ',' << matches_cold << ','
            << (reference.answered ? reference.status : "NO_REPLY") << ','
            << (same_outcome(row.result, reference) ? 1 : 0) << ',' << (shares ? (*shares ? "1" : "0") : "") << '\n';
    }

    // Summary table, one line per mode.
    std::cout << "\n"
              << mix << ": " << lookups.size() << " names x " << trials << " trial(s), written to " << out_path
              << "\n\n";
    std::cout << std::left << std::setw(10) << "mode" << std::right << std::setw(9) << "p50 ms" << std::setw(9)
              << "p95 ms" << std::setw(14) << "queries/look" << std::setw(11) << "hit ratio" << std::setw(13)
              << "outcome=ref" << std::setw(13) << "shares addr" << std::setw(13) << "warm=cold" << '\n';
    for (const std::string mode : {"no-cache", "cold", "warm"}) {
        std::vector<double> latencies;
        double queries = 0;
        int hits = 0;
        int agree = 0;
        int shared = 0;
        int both_answered = 0;
        int same = 0;
        int count = 0;
        for (const Row& row : rows) {
            if (row.mode != mode) {
                continue;
            }
            ++count;
            latencies.push_back(row.latency_ms);
            queries += row.result.upstream_queries;
            hits += row.result.upstream_queries == 0;
            agree += same_outcome(row.result, references.at(row.lookup));
            if (const std::optional<bool> shares = shares_record(row.result, references.at(row.lookup))) {
                ++both_answered;
                shared += *shares;
            }
            if (mode == "warm") {
                const Row* cold = cold_rows.at({row.trial, row.lookup});
                same += row.result.status == cold->result.status &&
                        answer_set(row.result.answers) == answer_set(cold->result.answers);
            }
        }
        std::cout << std::left << std::setw(10) << mode << std::right << std::fixed << std::setprecision(1)
                  << std::setw(9) << percentile(latencies, 0.50) << std::setw(9) << percentile(latencies, 0.95)
                  << std::setw(14) << queries / count << std::setw(10) << 100.0 * hits / count << '%' << std::setw(12)
                  << 100.0 * agree / count << '%' << std::setw(12)
                  << (both_answered ? 100.0 * shared / both_answered : 0.0) << '%';
        if (mode == "warm") {
            std::cout << std::setw(12) << 100.0 * same / count << '%';
        } else {
            std::cout << std::setw(13) << "-";
        }
        std::cout << '\n';
    }
    return 0;
}
