# Team coding style

Every team member (and any AI assistant they use) follows this file. If you use an
AI assistant, paste the **Prompt** section below into it before you start.

---

## Prompt

> You are helping with a C++17 group project: an iterative DNS resolver built from
> scratch (no DNS libraries). I own one module, and teammates own the others. The
> code will be merged from separate branches, so follow these rules exactly.
>
> **Scope**
> - Only create or edit files inside my module folder (listed under "Who owns what"
>   below). Never edit another module's files, the shared headers in `src/dns/` and
>   `src/net/`, or the top-level `CMakeLists.txt`. If something shared needs to
>   change, stop and tell me so I can talk to the team.
> - Do not reformat, rename or "tidy up" code you were not asked to touch.
> - Keep it simple: this needs to work for a couple of demo lookups, not every edge case.
>
> **Language and libraries**
> - C++17, standard library only. No `<bits/stdc++.h>`, no Boost, no DNS libraries.
> - Use the shared types from `dns/message.h`, `dns/codec.h` and `net/transport.h`.
>   Do not write a second encoder, decoder or socket wrapper.
> - Sockets only through `net/socket_compat.h` (so the code builds on Windows and Linux).
>
> **Naming**
> - Types, structs, enums, classes: `PascalCase` (`ResolveResult`, `CacheEntry`).
> - Functions, variables, parameters, file names: `snake_case` (`resolve_name`, `server_ip`, `cache.cpp`).
> - Private class members: `snake_case_` with a trailing underscore (`entries_`).
> - Constants: `kPascalCase` (`kMaxHops`). Enum values: `PascalCase` (`RecordType::CNAME`, `Rcode::NxDomain`).
> - Everything lives in `namespace dns`. Helpers used by one `.cpp` go in an anonymous namespace there.
>
> **Formatting** (enforced by `.clang-format`; run `clang-format -i` on your files before committing)
> - 4-space indent, no tabs, 120-column limit.
> - Braces on the same line, and always use braces, even for one-line `if`s.
> - `#pragma once` in headers. Include order: own header first, then standard headers,
>   then project headers (`"dns/codec.h"`), with a blank line between groups.
> - Never `using namespace` in a header.
>
> **Error handling**
> - Malformed packets: `decode()` throws `dns::ParseError`. Catch it where you call
>   `decode()` and treat that response as unusable (try the next server); never let it crash the program.
> - Expected failures (timeout, no answer, not found) are return values (`std::optional`,
>   a result struct with a status), not exceptions.
> - No `exit()` inside library code. Only `main()` decides the exit code.
>
> **DNS conventions**
> - Names have no trailing dot; the root is `""`. Compare with `names_equal()`.
> - Send queries with `rd = false` (we resolve iteratively).
> - Random 16-bit query IDs (`std::random_device` / `std::mt19937`).
>
> **Comments**
> - Short comments that explain *why*, not *what*. A one-line comment on each public
>   function in a header. No commented-out code, no `// TODO` left without a name.
>
> **Tests and tools**
> - Tests go next to the code (`src/<module>/<thing>_test.cpp`), use `common/check.h`
>   (`CHECK`, `CHECK_THROWS`), and are registered in your module's `CMakeLists.txt`
>   with `add_test`. Tests must not need the internet.
> - Your module's `CMakeLists.txt` defines a library named `dns_<module>`.

---

## Who owns what

| Folder | Library | Owner |
|---|---|---|
| `src/dns/` (message, codec) | `dns_codec` | Riya (shared: changes go through `main`) |
| `src/net/` (sockets, transport) | `dns_net` | Kavish (shared: changes go through `main`) |
| `src/resolver/` | `dns_resolver` | Ojaswit |
| `src/cache/` | `dns_cache` | Bhardwaaj |
| `src/server/` | `dns_server` | Ojaswit |
| `src/common/` | (header only) | shared, don't edit |

The top-level `CMakeLists.txt` already includes every folder above if it exists, so
nobody needs to edit it.

## Git workflow

1. Start your branch from the latest `main`: `git switch main`, `git pull`, `git switch -c feature/<module>`.
2. Commit small and often. Message format: `<module>: <what changed>`, for example `resolver: follow NS referrals using glue`.
3. When `main` changes (codec or transport improvements), merge it into your branch:
   `git merge main`. Small, frequent merges stay painless.
4. Shared headers (`src/dns/*.h`, `src/net/*.h`) may only gain new things. Changing or
   removing an existing function or struct field needs the whole team to agree first.

## Build and test

```
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

Try a live query against a root server:

```
build/tools/dns_query 198.41.0.4 example.com A
```
