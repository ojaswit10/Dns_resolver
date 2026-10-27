# Iterative DNS Resolver with Caching: Project Report

**Course:** CS-30003 · Coding Assignment 1 · Project P2 (Path A)
**Repository:** https://github.com/ojaswit10/Dns_resolver

| Member | Roll no. | Component |
|---|---|---|
| Ojaswit Singh | 24052398 | Iterative resolution engine, DNS server mode, experiment |
| Riya Koshyari | 2405015 | Wire-format codec |
| Bhardwaaj Singh | 24159004 | Caching layer |
| Kavish Tewari | 24155704 | Transport layer (UDP, TCP fallback) |

---

## 1. Summary

We built a DNS resolver and caching DNS server from scratch in C++17, using only POSIX
or Winsock sockets and no DNS libraries. It does not forward questions to an existing
resolver such as 8.8.8.8. It performs **full iterative resolution**, starting at the
root servers and following referrals down through the TLD servers to the authoritative
server for each name. Messages are encoded and decoded by our own implementation of the
RFC 1035 wire format, including name compression.

The server answers real clients: Windows `nslookup` resolves names through it, and an
operating system can be pointed at it for normal browsing.

We tested the claim from our proposal: *a warm cache answers repeated queries with much
lower latency and far fewer upstream queries than a resolver that walks from the root
every time, without changing the answers.* Over 540 measured lookups the claim held:

- Median latency fell from **414–650 ms to under 1 ms**.
- Upstream queries per lookup fell from **about 5 to 0**.
- Warm answers equalled cold answers in **100%** of lookups.
- The outcome matched Cloudflare's public resolver for **every** lookup.

## 2. Background

DNS maps names such as `www.github.com` to records such as IP addresses. The data is
split into **zones** arranged as a tree. The 13 root servers know only which servers run
each top-level domain. The `.com` servers know only which servers run each `.com`
domain, and so on down. An **iterative resolver** finds an answer by walking down this
tree:

1. Ask a root server. It replies with a **referral**: NS records for `com`, plus the
   addresses of those servers (**glue**) in the additional section.
2. Ask a `com` server. It refers us to `github.com`'s servers.
3. Ask a `github.com` server. It returns the answer, here a CNAME
   `www.github.com → github.com` and then an A record.

Every answer has a **TTL** saying how long it may be cached. "This name does not exist"
(NXDOMAIN) and "this name has no records of this type" (NODATA) can be cached too, for
a time taken from the zone's SOA record (RFC 2308).

## 3. Design

The system is split into four modules with narrow interfaces, one per team member, so
work could proceed in parallel on separate branches:

```
 client ─UDP─▶ server ──▶ resolver ──▶ cache          (hit: answer immediately)
                              │
                              └──▶ transport ──UDP/TCP──▶ root / TLD / authoritative servers
                                       ▲
                      codec ───────────┘  (every module speaks dns::Message)
```

| Module | Folder | Responsibility |
|---|---|---|
| Codec | `src/dns` | `Message`/`ResourceRecord` types; `encode()`, `decode()`, `make_query()` |
| Transport | `src/net` | `send_udp`, `send_tcp`, `send_query` (UDP, then TCP when truncated); portable sockets |
| Cache | `src/cache` | Positive and negative records with expiry times |
| Resolver | `src/resolver` | The iterative walk, CNAME following, safety limits |
| Server | `src/server` | Listens for client queries, resolves them, builds replies |

To keep the separate branches easy to merge:
- The shared types and interfaces were committed to `main` before anyone branched.
- A style guide (`STYLE.md`, plus `.clang-format`) fixed naming, formatting and error
  handling for everyone.
- Each module's build file lives in its own folder.
- `.gitattributes` forces the same line endings on every machine.

As a result, all four branches merged into `main` with **no conflicts**.

## 4. Implementation

### 4.1 Codec (RFC 1035)

- **Encoding** writes the 12-byte header, the questions and the resource records in
  network byte order. **Name compression** is generated: the encoder remembers where
  each name suffix was written, and replaces repeated suffixes with a 2-byte pointer
  (`0xC000 | offset`).
- **Decoding** follows compression pointers, with these protections:
  - A pointer must point *backwards*, which rules out self-references and loops.
  - At most 64 jumps per name.
  - Labels are at most 63 bytes and names at most 255 bytes.
  - Every read is bounds-checked.
  - Malformed input throws `ParseError` instead of crashing or reading out of bounds.
- **Record data** is decoded for A, AAAA (formatted per RFC 5952), NS, CNAME, MX, SOA
  and TXT. Unknown types (for example HTTPS, type 65) are kept as raw bytes, so they
  survive a decode/encode round trip.
- **Hardening** (Riya): the codec also rejects
  - names longer than 255 bytes when encoding
  - oversized RDATA or section counts
  - leftover bytes inside NS/CNAME/MX/SOA data
  - extra bytes after the last record of a packet

### 4.2 Transport

- `send_udp` sends a query and waits with a timeout and retry. It accepts only a reply
  that comes from the server it asked and carries the same 16-bit query ID; anything
  else is ignored.
- `send_tcp` (Kavish) uses the 2-byte length prefix from RFC 1035 §4.2.2. It reads
  until the whole message has arrived, because TCP may deliver it in pieces, and it
  uses a non-blocking connect so that connecting can time out.
- `send_query` uses UDP first and repeats the question over TCP when the reply has the
  **TC (truncated)** bit set. This matters in practice: root referrals don't fit in
  512 bytes, and with TCP fallback the resolver receives all 13 `.com` server
  addresses instead of 6–7.
- `socket_compat` hides the differences between Winsock and POSIX, so the same code
  builds on Windows and Linux.

### 4.3 Cache (RFC 2308)

- **Positive records** are keyed by (name, type, class), with names lowercased, and
  stored with an absolute expiry time. `get()` drops expired entries and returns the
  remaining TTL, so answers served from the cache count down correctly.
- **Negative entries** are stored per name for NXDOMAIN and per (name, type) for
  NODATA. Their lifetime is `min(SOA TTL, SOA minimum)`, as RFC 2308 specifies.
- Storing a record **replaces** an identical cached record instead of duplicating it.
  New positive data also clears any matching negative entry.

### 4.4 Resolver

`resolve(name, type)` repeats the following until it has an answer:

1. **Check the cache**, in this order:
   - a negative entry, which returns NXDOMAIN or NODATA immediately
   - matching records, which are returned
   - a CNAME for the name, which is followed
2. **Start from the closest known servers.** Look in the cache for NS records of the
   name, then of its parent, and so on up the tree, and start from the deepest zone
   whose server addresses are known. Only with nothing cached does the walk start at
   the root hints.
3. **Walk down.** Each reply is classified as one of:

| Reply | Action |
|---|---|
| Records of the requested type | Done. Cache them |
| CNAME | Record the alias. Follow it within the same reply if the target is in the server's zone, otherwise resolve the target separately |
| Referral (NS for a zone strictly between the current zone and the name) | Cache NS and glue, then ask the new zone's servers |
| Referral with no glue | Resolve the nameserver's own name as a nested lookup, then continue |
| NXDOMAIN / NODATA with SOA | Return it and cache it negatively |
| Timeout, malformed reply, SERVFAIL, REFUSED, or a **lame** reply | Try the next server of the zone |

**Bailiwick checking.** A record is accepted only if its name lies inside the zone of
the server that sent it. Glue is likewise accepted only from inside the referring
server's zone. This stops a server from planting answers for domains it has no
authority over. The test suite checks this with a fake server that tries to inject an
out-of-zone address.

**Loop and depth protection:**
- at most 60 upstream queries per lookup, counted across nested lookups
- at most 8 CNAME hops
- at most 4 levels of nested "resolve the nameserver" lookups

A test with a CNAME loop (`loop1 → loop2 → loop1`) confirms that resolution stops with
SERVFAIL.

**Query hygiene.** Every query gets a random ID and is sent with `RD = 0`, because we
resolve iteratively ourselves and don't ask the servers to recurse for us.

### 4.5 Server

- Listens on UDP (default `127.0.0.1:53`) and resolves each query on its own thread,
  so one slow lookup doesn't block the others. Up to 64 queries can be in flight.
- One cache is shared between all threads. The resolver takes a lock around every
  cache call, but never holds it during network I/O.
- Replies echo the client's ID, question and RD flag, and set RA. Negative replies
  include the SOA record and keep any CNAME chain that led to them.
- Malformed packets get FORMERR, unsupported opcodes or classes get NOTIMP, and
  responses sent to the server are ignored.
- **EDNS:** clients that send an OPT record get one back, and their reply size limit is
  raised from 512 bytes to up to 1232. A reply that is still too big is sent with TC
  set.

## 5. Testing

All tests run offline, against fake nameservers.

| Suite | What it covers |
|---|---|
| `codec_test` (37 checks) | Exact query bytes, header flags, compression pointer placement, round trip of every record type, root name, malformed packets (self- and forward pointers, truncation, bad RDATA length), size limits |
| `transport_test` (34 checks) | UDP reply, wrong ID ignored, retry after loss, timeout, TC triggers TCP fallback, TCP reply split across reads, connection refused, skipping bad servers |
| `cache_test` (10 checks) | TTL expiry, negative caching, duplicate replacement |
| `resolver_test` (34 checks) | Cold vs. warm, starting from a cached delegation, in-zone and cross-zone CNAMEs, glueless delegation, out-of-bailiwick record rejected, NXDOMAIN/NODATA cached, unreachable server, lame server, CNAME loop, no duplicate cache entries |
| `server_test` (23 checks) | Answers, cache reuse, NXDOMAIN with SOA, truncation vs. EDNS, FORMERR/NOTIMP/ignoring responses, real-socket test with 20 parallel clients |

The resolver tests use a fake DNS hierarchy (`root → test → example.test`,
`provider.test`, `other.test`, `lame.test`) injected through `ResolverOptions::query`,
so every resolution path runs without the internet.

**Live validation:**
- `resolve` gave correct answers for A, AAAA, MX, TXT and CNAME lookups, NXDOMAIN, and
  multi-level TLDs such as `.ac.in` and `.co.uk`.
- `serve` answered Windows `nslookup`: CNAME chains, IPv6 addresses, NXDOMAIN, MX, and
  repeat queries served from the cache with 0 upstream queries.

## 6. Experiment

### 6.1 Method

`tools/experiment` replays a fixed list of lookups in three modes, three trials each:

- **no-cache:** every lookup walks from the root. This is the "cold resolver every time"
  baseline, the same walk `dig +trace` performs.
- **cold:** one cache that starts empty. Later names may reuse delegations learned
  from earlier ones.
- **warm:** the same cache, replaying the same list again.

**Variables:** cache state and query mix.
- *popular*: 30 lookups of large sites.
- *long-tail*: 30 lookups of smaller sites across `.ac.in`, `.co.uk`, `.de`, `.jp`,
  `.ch`, `.nl`, `.au`, `.org` and others, plus two names that don't exist.

**Controls:** identical lists, root hints and timeout/retry settings (1.5 s, one
attempt per server) in every run.

**Metrics:** p50 and p95 latency; upstream queries per lookup; cache hit ratio
(lookups answered with 0 upstream queries).

**Correctness:**
- whether warm answers exactly equal cold answers
- whether the outcome matches Cloudflare's public resolver 1.1.1.1
- whether at least one returned record is shared with 1.1.1.1

### 6.2 Results

| Mix | Mode | p50 | p95 | Queries / lookup | Hit ratio | Same outcome as 1.1.1.1 | Shares a record | Warm = cold |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| popular | no-cache | 414 ms | 2102 ms | 4.81 | 0% | 100% | 80% | - |
| popular | cold | 205 ms | 682 ms | 2.70 | 0% | 100% | 81% | - |
| popular | warm | 0 ms | 0 ms | 0.00 | 100% | 100% | 81% | 100% |
| long-tail | no-cache | 650 ms | 1967 ms | 5.18 | 0% | 100% | 100% | - |
| long-tail | cold | 376 ms | 1096 ms | 3.42 | 0% | 100% | 100% | - |
| long-tail | warm | 0 ms | 0 ms | 0.00 | 100% | 100% | 100% | 100% |

Charts: `experiment/results/latency.svg` and `experiment/results/queries.svg`. Raw
data: `experiment/results/*.csv`.

### 6.3 Analysis

- **The claim is supported.** Warm lookups needed no upstream queries and completed in
  under a millisecond, compared with medians of 414 ms (popular) and 650 ms (long-tail)
  for a full walk. The p95 gap is even larger (about 2 s down to 0), because slow or
  unreachable nameservers dominate the tail of cold lookups.
- **Most of the benefit comes from caching delegations, not just answers.** Even the
  *cold* pass cut queries per lookup by 44% (popular) and 34% (long-tail), and median
  latency by about half. That's because later names reuse NS and glue records for
  `com`, `org` and so on learned by earlier ones. This is why the resolver looks up
  the closest cached zone before falling back to the root.
- **Query mix matters only when the cache is cold.** Long-tail names are spread across
  more TLDs, so there are fewer delegations to share (3.42 vs. 2.70 queries per cold
  lookup). Once the cache is warm, both mixes cost nothing.
- **Correctness is not sacrificed.**
  - Warm answers matched cold answers in every case.
  - The outcome matched 1.1.1.1 for all 540 lookups.
  - The popular lookups that shared no address with 1.1.1.1 were all large CDN-backed
    sites (Google, YouTube, WhatsApp, Microsoft, X). These sites deliberately answer
    each resolver with servers near it, so different addresses are expected.

### 6.4 Threats to validity

- Results come from a single network location and date; latencies depend on distance
  to the nameservers.
- The warm pass replays the list within seconds, so no TTL expires in between. With
  long gaps between repeats, the hit ratio would fall towards each record's TTL
  behaviour.
- Each mix has only 30 lookups. The trends were consistent across all three trials.

## 7. Problems found and solved

1. **Lame nameserver.** `dns2.openbsd.org` answers questions about `openbsd.org`
   without authority, referring back to its own zone. The first version of the resolver
   returned SERVFAIL whenever it picked that server, which showed up in the experiment
   as intermittent failures. The resolver now treats such replies as "try the next
   server". A regression test models the exact behaviour, and the fix took
   `openbsd.org` from occasional failures to 0 failures in 12 runs.
2. **Truncated root referrals.** Without EDNS, root replies exceed 512 bytes and arrive
   with TC set. Switching the resolver to `send_query` (UDP, then TCP) restored the full
   set of 13 TLD server addresses.
3. **NXDOMAIN vs. NODATA disagreement.** For names that don't exist in
   Cloudflare-hosted zones, the authoritative server tells our (non-DNSSEC) resolver
   NXDOMAIN, but tells validating resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9) NOERROR with no
   records. This is "compact denial of existence". We confirmed it by querying the
   authoritative server directly, and the experiment counts both answers as the same
   "no records" outcome.
4. **Platform issues on Windows:**
   - Windows headers define `IN` as an empty macro, which broke `RecordClass::IN`; it
     is now undefined in `socket_compat.h`.
   - Port 5353 is taken by multicast DNS.
   - Windows `nslookup` ignores `-port`, so we test on port 53.
   - The network's DNS search suffix gets appended to names unless they end in a dot.
5. **Thread safety.** The cache is not thread-safe, so the server gives the resolver a
   mutex that it takes around every cache call, never during network I/O.

## 8. Limitations and future work

- Nameservers are contacted over IPv4 only (AAAA records can still be resolved). Adding
  IPv6 transport would let the resolver use IPv6-only nameservers.
- No DNSSEC validation.
- The server answers over UDP only. Adding a TCP listener would serve clients that
  retry after TC.
- The cache is in memory and unbounded. An LRU size limit and pre-fetching popular
  records before they expire would help a long-running server.
- Servers are tried in the order they arrive. Tracking each server's round-trip time
  and preferring the fastest (as BIND and Unbound do) would reduce cold p95 latency.

## 9. Contributions

| Member | Contribution |
|---|---|
| Ojaswit Singh | Shared message types and initial codec/transport on `main`; style guide and build layout; iterative resolution engine (referrals, glue, glueless lookups, CNAME chains, bailiwick, lame servers, limits); caching DNS server; experiment harness, measurements and analysis; integration and merging |
| Riya Koshyari | Codec hardening: name, RDATA and section size limits, structured-RDATA and trailing-byte validation, strict numeric type parsing, extra negative tests |
| Bhardwaaj Singh | Cache: TTL-based storage and expiry, RFC 2308 negative caching, replacement of duplicate records, tests |
| Kavish Tewari | Transport: TCP with length-prefix framing, connect timeouts, TCP fallback on TC, multi-server querying, loopback test suite |

## 10. References

- RFC 1034: Domain Names, Concepts and Facilities
- RFC 1035: Domain Names, Implementation and Specification
- RFC 2308: Negative Caching of DNS Queries
- RFC 3597: Handling of Unknown DNS Resource Record Types
- RFC 5952: A Recommendation for IPv6 Address Text Representation
- RFC 6891: Extension Mechanisms for DNS (EDNS(0))
- RFC 7766: DNS Transport over TCP, Implementation Requirements
- IANA Root Servers: https://www.iana.org/domains/root/servers
