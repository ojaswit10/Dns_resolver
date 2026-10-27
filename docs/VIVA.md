# Viva preparation

A demo you can run in about five minutes, followed by the questions examiners are likely
to ask, with short answers that point at our own code and results.

## Demo script

Build first, so nothing compiles during the viva:

```bash
cmake -S . -B build -G Ninja && cmake --build build && ctest --test-dir build
```

1. **Tests pass offline:** `ctest --test-dir build` shows 5/5 suites passing.
2. **One raw query, to show the wire format at work:** ask a root server directly.
   It doesn't know the answer and sends a referral with glue.
   ```bash
   ./build/tools/dns_query 198.41.0.4 www.github.com A
   ```
3. **The full iterative walk, then the cache:**
   ```bash
   ./build/src/resolver/resolve www.github.com A --repeat 2
   ```
   Point out: root → `com` → `github.com`, the CNAME, 3 upstream queries the first
   time and **0** the second time.
4. **The server with a real client.** In one terminal:
   ```bash
   ./build/src/server/serve
   ```
   In another:
   ```bash
   nslookup www.github.com. 127.0.0.1
   nslookup www.github.com. 127.0.0.1
   nslookup nosuchname-zz9.example.com. 127.0.0.1
   ```
   Point out in the server log: first lookup 3 upstream, repeat 0 upstream, NXDOMAIN.
5. **The experiment results:** open `experiment/results/latency.svg` and the table in
   the README.

## Likely questions

### DNS basics

**Iterative vs. recursive resolution?**
A recursive resolver (like 8.8.8.8) takes a question and does all the work. Our
resolver *is* the thing doing that work, iteratively: it asks the root, follows the
referral to the TLD, then to the authoritative server. We send every upstream query with
`RD = 0` because we don't want any server recursing for us.

**What is glue, and why is it needed?**
A referral says "ask `ns1.example.com`" for `example.com`. To reach that server you need
its address, but its address lives inside the zone you're trying to reach, which is a
chicken-and-egg problem. The parent zone therefore includes the address in the
additional section. That address is glue.

**What if a referral has no glue?**
For example, `other.test` delegated to `ns.provider.test`. The resolver resolves the
nameserver's name as a separate, nested lookup, then continues. The nesting is limited to
4 levels so that a delegation pointing to itself can't loop forever
(`nameserver_ips()` in `resolver.cpp`; test `test_out_of_zone_cname_and_glueless_delegation`).

**How do you handle CNAMEs?**
If the reply contains a CNAME for the name, we record it and continue with the target.
If the same server is authoritative for the target, the next record is usually in the
same reply. Otherwise we resolve the target separately, from the cache or the root. The
answer we return is the whole chain. There's a limit of 8 hops, and a test with a CNAME
loop confirms it stops.

**NXDOMAIN vs. NODATA?**
NXDOMAIN means the name doesn't exist at all. NODATA means the name exists but has no
records of the requested type (NOERROR with an empty answer). Both are cached
negatively, for `min(SOA TTL, SOA minimum)` seconds (RFC 2308).

**Why UDP, and when is TCP used?**
UDP is one packet each way, so it's fast. A plain DNS reply over UDP is limited to 512
bytes. If the answer doesn't fit, the server sets the TC (truncated) bit, and the client
must ask again over TCP. Root referrals actually do this: with TCP fallback we get all
13 `.com` server addresses instead of 6–7.

### The wire format

**How does name compression work?**
A name is written as length-prefixed labels: `7 example 3 com 0`. If a name, or the end
of one, has already been written earlier in the packet, it is replaced by a 2-byte
pointer whose top two bits are `11`, with the remaining 14 bits holding the offset. For
example, `C0 0C` means "the name at byte 12", which is where the question name starts.

**How do you stop a malicious packet from crashing the parser?**
- Every read is bounds-checked.
- A compression pointer must point *backwards*, which rules out self-pointing and loops,
  and there are at most 64 jumps per name.
- Labels are at most 63 bytes and names at most 255.
- RDATA must match its declared length.
- Any violation throws `ParseError`. The resolver catches it and tries the next server.
- `codec_test` includes self-pointers, forward pointers, truncated labels and bad
  A-record lengths.

**How do you match a reply to its query?**
The query ID is random. The transport only accepts a reply from the IP and port it sent
to, carrying the same ID, and the resolver also checks the question section matches.
That makes blind spoofing much harder.

### Design choices

**What is bailiwick checking?**
A server may only tell us about names inside its own zone. If the `example.com` server
includes an A record for `bank.com`, we ignore it; otherwise any server could poison our
cache. The test `test_out_of_zone_cname_and_glueless_delegation` has a fake server inject
`6.6.6.6` for another zone and checks it is ignored.

**Why does even the *cold* cache help so much?**
Because the resolver also caches NS and glue records, and starts each lookup from the
closest zone it already knows. After the first `.com` name, every other `.com` name
skips the root entirely. In the experiment this cut queries per lookup by 34–44% within
a single cold pass.

**What is a lame server, and how did you find one?**
A server listed as authoritative for a zone that doesn't actually answer for it.
`dns2.openbsd.org` replies without authority and refers back to the same zone. The
experiment showed intermittent SERVFAIL for `www.openbsd.org`; the trace showed it
happened only when that server was picked. We now treat such replies as "try the next
server", and added a test that models the exact behaviour.

**How does the server handle many clients?**
Each query runs on its own thread, up to 64 at a time, so one slow lookup doesn't block
the others. All threads share one cache, protected by a mutex that the resolver takes
only around cache calls, never while waiting on the network. `server_test` sends 20
queries in parallel over a real socket.

**What protects against runaway lookups?**
At most 60 upstream queries per lookup (across nested lookups), 8 CNAME hops, and 4
levels of glueless nesting. Every server failure (timeout, malformed reply, SERVFAIL,
REFUSED, lame) moves on to the next server instead of retrying forever.

### The experiment

**What exactly did you measure?**
- 30 popular and 30 long-tail lookups, each in three modes: no-cache (a full walk each
  time, like `dig +trace`), cold (an empty cache filling up) and warm (a second pass).
- Three trials, 540 lookups in total.
- Metrics: p50/p95 latency, upstream queries per lookup, and cache hit ratio.

**How do you know caching didn't break correctness?**
- Warm answers equalled cold answers in 100% of lookups.
- Every answer was also compared with 1.1.1.1: the outcome ("found" vs "doesn't
  exist") matched for all 540 lookups.

**Why do 20% of popular lookups not share an address with 1.1.1.1?**
They are Google, YouTube, WhatsApp, Microsoft and X. These sites give each resolver the
addresses of servers near it (geo load balancing), so different resolvers see different
but equally valid addresses.

**Why did 1.1.1.1 say NOERROR for a name you said was NXDOMAIN?**
Cloudflare's authoritative servers use "compact denial of existence". They answer
NXDOMAIN to plain queries like ours, but NOERROR with no records to DNSSEC-validating
resolvers. We confirmed this by asking the authoritative server directly. Both mean "no
records", so the comparison treats them as the same outcome.

**What would weaken your result?**
- One location and one day.
- The warm pass runs seconds after the cold one, so no TTL has expired yet.
- Lists of only 30 names.

The direction of the result was the same in every trial, though.

### Limitations

**What doesn't it do?**
- Nameservers are reached over IPv4 only.
- No DNSSEC validation.
- The server has no TCP listener.
- The cache is in memory and has no size limit.
- Servers are tried in order, without measuring which one is fastest.

See section 8 of the report for how we would fix each.
