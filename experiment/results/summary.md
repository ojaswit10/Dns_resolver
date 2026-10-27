| Mix | Mode | Lookups | p50 latency (ms) | p95 latency (ms) | Upstream queries / lookup | Cache hit ratio | Same outcome as 1.1.1.1 | Shares an address with 1.1.1.1 | Warm = cold |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| popular | no-cache | 90 | 414.4 | 2101.6 | 4.81 | 0% | 100% | 80% | - |
| popular | cold | 90 | 204.5 | 682.1 | 2.70 | 0% | 100% | 81% | - |
| popular | warm | 90 | 0.0 | 0.0 | 0.00 | 100% | 100% | 81% | 100% |
| long_tail | no-cache | 90 | 650.2 | 1966.8 | 5.18 | 0% | 100% | 100% | - |
| long_tail | cold | 90 | 376.1 | 1096.2 | 3.42 | 0% | 100% | 100% | - |
| long_tail | warm | 90 | 0.0 | 0.0 | 0.00 | 100% | 100% | 100% | 100% |
