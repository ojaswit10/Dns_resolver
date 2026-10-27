"""Summarises experiment CSVs and draws the charts for the report.

Standard library only, so it runs on any Python 3.8+ without installing anything.

    python experiment/plot.py experiment/results/popular.csv experiment/results/long_tail.csv -o experiment/results

Writes summary.md (the cache-hit-ratio table), latency.svg and queries.svg.
"""

import argparse
import csv
import math
import os
from collections import defaultdict

MODES = ["no-cache", "cold", "warm"]
MODE_COLORS = {"no-cache": "#c0392b", "cold": "#e1a031", "warm": "#1f7a8c"}
MODE_LABELS = {
    "no-cache": "no cache (full walk every time)",
    "cold": "cold cache (starts empty)",
    "warm": "warm cache (second pass)",
}


def percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[min(rank, len(ordered)) - 1]


def load(paths):
    rows = []
    for path in paths:
        with open(path, newline="") as handle:
            rows.extend(csv.DictReader(handle))
    return rows


def summarise(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[(row["mix"], row["mode"])].append(row)

    summary = {}
    for key, items in groups.items():
        latencies = [float(r["latency_ms"]) for r in items]
        warm_checks = [r["matches_cold"] for r in items if r["matches_cold"] != ""]
        shares = [r["shares_record_with_reference"] for r in items if r["shares_record_with_reference"] != ""]
        summary[key] = {
            "lookups": len(items),
            "p50": percentile(latencies, 0.50),
            "p95": percentile(latencies, 0.95),
            "queries": sum(int(r["upstream_queries"]) for r in items) / len(items),
            "hit_ratio": 100.0 * sum(int(r["cache_hit"]) for r in items) / len(items),
            "same_outcome": 100.0 * sum(int(r["same_outcome_as_reference"]) for r in items) / len(items),
            "shares": (100.0 * shares.count("1") / len(shares)) if shares else None,
            "warm_same": (100.0 * warm_checks.count("1") / len(warm_checks)) if warm_checks else None,
        }
    return summary


def mixes_in(summary):
    seen = []
    for mix, _ in summary:
        if mix not in seen:
            seen.append(mix)
    return seen


def write_table(summary, path):
    lines = [
        "| Mix | Mode | Lookups | p50 latency (ms) | p95 latency (ms) | Upstream queries / lookup "
        "| Cache hit ratio | Same outcome as 1.1.1.1 | Shares an address with 1.1.1.1 | Warm = cold |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]

    def percent(value):
        return "-" if value is None else f"{value:.0f}%"

    for mix in mixes_in(summary):
        for mode in MODES:
            s = summary.get((mix, mode))
            if not s:
                continue
            lines.append(
                f"| {mix} | {mode} | {s['lookups']} | {s['p50']:.1f} | {s['p95']:.1f} | {s['queries']:.2f} "
                f"| {s['hit_ratio']:.0f}% | {percent(s['same_outcome'])} | {percent(s['shares'])} "
                f"| {percent(s['warm_same'])} |"
            )
    with open(path, "w") as handle:
        handle.write("\n".join(lines) + "\n")
    return lines


def nice_ceiling(value):
    if value <= 0:
        return 1.0
    magnitude = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 2.5, 5, 10):
        if value <= step * magnitude:
            return step * magnitude
    return 10 * magnitude


def grouped_bars(path, title, y_label, groups, values, whiskers=None, value_format="{:.0f}"):
    """values[(group, mode)] -> bar height; whiskers[(group, mode)] -> optional upper mark."""
    width, height = 760, 440
    left, right, top, bottom = 70, 20, 60, 110
    plot_w, plot_h = width - left - right, height - top - bottom

    highest = max([*values.values(), *(whiskers or {}).values(), 0])
    y_max = nice_ceiling(highest * 1.1)

    def y(v):
        return top + plot_h - (v / y_max) * plot_h

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'font-family="Segoe UI, Helvetica, Arial, sans-serif" font-size="13">',
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
        f'<text x="{width / 2}" y="30" text-anchor="middle" font-size="17" font-weight="600" fill="#222">{title}</text>',
    ]

    for i in range(6):
        tick = y_max * i / 5
        ty = y(tick)
        out.append(f'<line x1="{left}" y1="{ty:.1f}" x2="{width - right}" y2="{ty:.1f}" stroke="#e5e5e5"/>')
        out.append(f'<text x="{left - 8}" y="{ty + 4:.1f}" text-anchor="end" fill="#555">{tick:g}</text>')
    out.append(
        f'<text x="18" y="{top + plot_h / 2}" text-anchor="middle" fill="#333" '
        f'transform="rotate(-90 18 {top + plot_h / 2})">{y_label}</text>'
    )

    group_w = plot_w / len(groups)
    bar_w = group_w / (len(MODES) + 1.5)
    for g, group in enumerate(groups):
        x0 = left + g * group_w + bar_w * 0.75
        for m, mode in enumerate(MODES):
            if (group, mode) not in values:
                continue
            v = values[(group, mode)]
            x = x0 + m * bar_w
            out.append(
                f'<rect x="{x:.1f}" y="{y(v):.1f}" width="{bar_w * 0.9:.1f}" height="{y(0) - y(v):.1f}" '
                f'fill="{MODE_COLORS[mode]}"/>'
            )
            label_y = y(v) - 6
            if whiskers and (group, mode) in whiskers:
                w = whiskers[(group, mode)]
                cx = x + bar_w * 0.45
                out.append(f'<line x1="{cx:.1f}" y1="{y(v):.1f}" x2="{cx:.1f}" y2="{y(w):.1f}" stroke="#333"/>')
                out.append(f'<line x1="{cx - 6:.1f}" y1="{y(w):.1f}" x2="{cx + 6:.1f}" y2="{y(w):.1f}" stroke="#333"/>')
                label_y = min(label_y, y(w) - 6)
            out.append(
                f'<text x="{x + bar_w * 0.45:.1f}" y="{label_y:.1f}" text-anchor="middle" fill="#222">'
                f"{value_format.format(v)}</text>"
            )
        out.append(
            f'<text x="{left + g * group_w + group_w / 2:.1f}" y="{top + plot_h + 22}" text-anchor="middle" '
            f'font-weight="600" fill="#222">{group}</text>'
        )

    out.append(f'<line x1="{left}" y1="{y(0):.1f}" x2="{width - right}" y2="{y(0):.1f}" stroke="#999"/>')
    legend_y = height - 45
    for m, mode in enumerate(MODES):
        lx = left + m * 220
        out.append(f'<rect x="{lx}" y="{legend_y}" width="14" height="14" fill="{MODE_COLORS[mode]}"/>')
        out.append(f'<text x="{lx + 20}" y="{legend_y + 12}" fill="#333">{MODE_LABELS[mode]}</text>')
    if whiskers:
        out.append(
            f'<text x="{left}" y="{height - 12}" fill="#666">Bars show the median (p50); whiskers show p95.</text>'
        )
    out.append("</svg>")

    with open(path, "w") as handle:
        handle.write("\n".join(out) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("csv", nargs="+", help="CSV files written by the experiment tool")
    parser.add_argument("-o", "--out", default=".", help="directory for summary.md and the charts")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)
    summary = summarise(load(args.csv))
    groups = mixes_in(summary)

    table = write_table(summary, os.path.join(args.out, "summary.md"))
    grouped_bars(
        os.path.join(args.out, "latency.svg"),
        "Lookup latency: no cache vs cold vs warm",
        "milliseconds",
        groups,
        {k: v["p50"] for k, v in summary.items()},
        whiskers={k: v["p95"] for k, v in summary.items()},
    )
    grouped_bars(
        os.path.join(args.out, "queries.svg"),
        "Upstream queries per lookup",
        "queries sent to nameservers",
        groups,
        {k: v["queries"] for k, v in summary.items()},
        value_format="{:.2f}",
    )

    print("\n".join(table))
    print(f"\nwrote {args.out}/summary.md, latency.svg, queries.svg")


if __name__ == "__main__":
    main()
