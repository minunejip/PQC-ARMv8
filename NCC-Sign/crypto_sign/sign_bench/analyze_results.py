#!/usr/bin/env python3
"""
Benchmark result analyzer for NCC-Sign.
Reads a CSV file of cycle-count measurements and produces publication-ready
summary tables and a profiling breakdown.

Usage:
    python analyze_results.py [results.csv]
"""

import argparse
import os
import sys

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Profiling category mapping
# ---------------------------------------------------------------------------
CATEGORY_MAP = {
    "ntt": "NTT",
    "invntt": "INTT",
    "basemul": "Pointwise",
    "poly_uniform": "Sampling",
    "poly_uniform_eta": "Sampling",
    "poly_uniform_gamma1": "Sampling",
    "shake256_hash": "Hashing",
    "poly_challenge": "Hashing",
    "pack_pk": "Packing",
    "pack_sk": "Packing",
    "pack_sig": "Packing",
    "unpack_pk": "Packing",
    "unpack_sk": "Packing",
    "unpack_sig": "Packing",
    "polyw1_pack": "Packing",
}
# Everything not listed above falls into "Other".

CATEGORY_ORDER = ["NTT", "INTT", "Pointwise", "Sampling", "Hashing", "Packing", "Other"]

# ---------------------------------------------------------------------------
# Call counts per operation (optimized build)
# ---------------------------------------------------------------------------
CALL_COUNTS = {
    "keygen": {
        "poly_uniform": 1,
        "poly_uniform_eta": 2,
        "ntt": 1,
        "basemul": 1,
        "invntt": 1,
        "shake256_hash": 2,
        "pack_pk": 1,
        "pack_sk": 1,
        "poly_caddq": 2,
        "poly_add": 1,
        "poly_power2round": 1,
    },
    "sign_attempt": {
        "poly_uniform_gamma1": 1,
        "ntt": 2,
        "invntt": 4,
        "basemul": 4,
        "shake256_hash": 1,
        "poly_challenge": 1,
        "polyw1_pack": 1,
        "poly_decompose": 1,
        "poly_add": 2,
        "poly_sub": 1,
        "poly_reduce": 3,
        "poly_caddq": 4,
        "poly_chknorm": 3,
        "poly_make_hint": 1,
    },
    "verify": {
        "poly_uniform": 1,
        "ntt": 3,
        "invntt": 2,
        "basemul": 2,
        "shake256_hash": 3,
        "poly_challenge": 1,
        "unpack_pk": 1,
        "unpack_sig": 1,
        "polyw1_pack": 1,
        "poly_shiftl": 1,
        "poly_sub": 1,
        "poly_caddq": 3,
        "poly_chknorm": 1,
        "poly_use_hint": 1,
    },
}

# Map profile_* operations to their short names for the profiling table
PROFILE_OP_MAP = {
    "profile_keygen": "keygen",
    "profile_sign_attempt": "sign_attempt",
    "profile_verify": "verify",
}

PROFILE_OP_LABEL = {
    "keygen": "KeyGen",
    "sign_attempt": "Sign(att)",
    "verify": "Verify",
}

# Friendly labels for the summary table
OP_LABELS = {
    ("keygen", "end2end"): "KeyGen",
    ("sign", "per_attempt"): "Sign(att)",
    ("sign", "full"): "Sign(full)",
    ("sign", "setup"): "Sign(setup)",
    ("verify", "end2end"): "Verify",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def fmt(x):
    """Format a number with thousands separators, no decimals."""
    if x is None or (isinstance(x, float) and np.isnan(x)):
        return "N/A"
    return f"{int(round(x)):,}"


def fmt_ci(lo, hi):
    """Format a 95 % confidence interval."""
    if lo is None or hi is None:
        return "N/A"
    return f"[{fmt(lo)} - {fmt(hi)}]"


def pick_primary_set(group_df):
    """
    For multi-set data (sets 1-10), pick the set whose mean is lowest.
    Returns filtered DataFrame (rows from the primary set only).
    For single-set / profile data (set == 0), return as-is.
    """
    sets = group_df["set"].unique()
    if len(sets) <= 1:
        return group_df
    means = group_df.groupby("set")["cycles"].mean()
    best = means.idxmin()
    return group_df[group_df["set"] == best]


def compute_stats(cycles):
    """Return a dict of summary statistics for a Series of cycle counts."""
    n = len(cycles)
    if n == 0:
        return {
            "median": np.nan, "mean": np.nan, "std": np.nan,
            "min": np.nan, "p5": np.nan, "p95": np.nan,
            "ci_lo": np.nan, "ci_hi": np.nan, "n": 0,
        }
    med = np.median(cycles)
    mn = np.mean(cycles)
    sd = np.std(cycles, ddof=1) if n > 1 else 0.0
    ci_half = 1.96 * sd / np.sqrt(n)
    return {
        "median": med,
        "mean": mn,
        "std": sd,
        "min": np.min(cycles),
        "p5": np.percentile(cycles, 5),
        "p95": np.percentile(cycles, 95),
        "ci_lo": mn - ci_half,
        "ci_hi": mn + ci_half,
        "n": n,
    }


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def load_csv(path):
    """Load and validate the CSV."""
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    df = pd.read_csv(path)
    expected_cols = {"param", "build", "operation", "metric", "set", "iteration", "cycles"}
    missing = expected_cols - set(df.columns)
    if missing:
        print(f"Error: CSV missing columns: {missing}", file=sys.stderr)
        sys.exit(1)
    df["cycles"] = pd.to_numeric(df["cycles"], errors="coerce")
    df.dropna(subset=["cycles"], inplace=True)
    return df


def build_summary(df):
    """
    Build a summary DataFrame with statistics for every
    (param, build, operation, metric) group.
    """
    rows = []
    grouped = df.groupby(["param", "build", "operation", "metric"], sort=False)
    for (param, build, operation, metric), grp in grouped:
        primary = pick_primary_set(grp)
        s = compute_stats(primary["cycles"].values)
        s.update({
            "param": param,
            "build": build,
            "operation": operation,
            "metric": metric,
            "primary_set": int(primary["set"].mode().iloc[0]) if len(primary) > 0 else 0,
        })
        rows.append(s)
    return pd.DataFrame(rows)


def get_stat(summary, param, build, operation, metric, stat="median"):
    """Safely retrieve a single statistic from the summary table."""
    mask = (
        (summary["param"] == param)
        & (summary["build"] == build)
        & (summary["operation"] == operation)
        & (summary["metric"] == metric)
    )
    subset = summary.loc[mask, stat]
    if subset.empty:
        return np.nan
    return subset.iloc[0]


def print_summary_tables(summary, df):
    """Print the main summary tables to stdout."""
    params = sorted(summary["param"].unique())
    for param in params:
        level = param.replace("Sign", "")  # "1", "3", "5"
        print(f"\n{'=' * 80}")
        print(f"=== NCC-Sign-{level} ===")
        print(f"{'=' * 80}")

        header = (
            f"{'Operation':<12} | {'Build':<5} | {'Median':>12} | {'Mean':>12} | "
            f"{'Std':>10} | {'95% CI':>25} | {'P5':>12} | {'P95':>12} | {'Min':>12}"
        )
        print(header)
        print("-" * len(header))

        # Which rows to show
        display_rows = [
            ("keygen", "end2end", "KeyGen"),
            ("sign", "per_attempt", "Sign(att)"),
            ("sign", "full", "Sign(full)"),
            ("sign", "setup", "Sign(setup)"),
            ("verify", "end2end", "Verify"),
        ]

        for op, met, label in display_rows:
            for build in ["clean", "optimized"]:
                build_label = "clean" if build == "clean" else "opt"
                mask = (
                    (summary["param"] == param)
                    & (summary["build"] == build)
                    & (summary["operation"] == op)
                    & (summary["metric"] == met)
                )
                row = summary.loc[mask]
                if row.empty:
                    print(f"{label:<12} | {build_label:<5} | {'N/A':>12} | {'N/A':>12} | "
                          f"{'N/A':>10} | {'N/A':>25} | {'N/A':>12} | {'N/A':>12} | {'N/A':>12}")
                    continue
                r = row.iloc[0]
                ci_str = fmt_ci(r["ci_lo"], r["ci_hi"])
                print(
                    f"{label:<12} | {build_label:<5} | {fmt(r['median']):>12} | "
                    f"{fmt(r['mean']):>12} | {fmt(r['std']):>10} | {ci_str:>25} | "
                    f"{fmt(r['p5']):>12} | {fmt(r['p95']):>12} | {fmt(r['min']):>12}"
                )

        # Speedup
        speedups = []
        for op, met, label in [
            ("keygen", "end2end", "KeyGen"),
            ("sign", "per_attempt", "Sign(per-att)"),
            ("sign", "full", "Sign(full)"),
            ("verify", "end2end", "Verify"),
        ]:
            c = get_stat(summary, param, "clean", op, met, "median")
            o = get_stat(summary, param, "optimized", op, met, "median")
            if not np.isnan(c) and not np.isnan(o) and o > 0:
                speedups.append(f"{label} {c / o:.2f}x")
            else:
                speedups.append(f"{label} N/A")
        print(f"\nSpeedup: {' | '.join(speedups)}")

        # Average rejections
        rej_parts = []
        for build in ["clean", "optimized"]:
            build_label = "clean" if build == "clean" else "opt"
            # Use the primary set for per_attempt and full
            att_mask = (
                (df["param"] == param)
                & (df["build"] == build)
                & (df["operation"] == "sign")
                & (df["metric"] == "per_attempt")
            )
            full_mask = (
                (df["param"] == param)
                & (df["build"] == build)
                & (df["operation"] == "sign")
                & (df["metric"] == "full")
            )
            att_df = df.loc[att_mask]
            full_df = df.loc[full_mask]
            # Pick primary set for each
            att_primary = pick_primary_set(att_df)
            full_primary = pick_primary_set(full_df)
            n_att = len(att_primary)
            n_full = len(full_primary)
            if n_full > 0:
                avg_rej = n_att / n_full
                rej_parts.append(f"{build_label} {avg_rej:.2f}")
            else:
                rej_parts.append(f"{build_label} N/A")
        print(f"Avg rejections: {' | '.join(rej_parts)}")


def print_profiling_tables(summary, df):
    """Print profiling breakdown tables (optimized build only)."""
    params = sorted(summary["param"].unique())
    profile_ops = ["keygen", "sign_attempt", "verify"]

    for param in params:
        level = param.replace("Sign", "")
        print(f"\n{'=' * 80}")
        print(f"=== NCC-Sign-{level} Profiling (Optimized) ===")
        print(f"{'=' * 80}")

        # Gather median cycles for each function from optimized build's profile data
        # CSV format: operation="profile", metric=<function_name>
        med_cache = {}  # func_name -> median cycles
        mask = (
            (summary["param"] == param)
            & (summary["build"] == "optimized")
            & (summary["operation"] == "profile")
        )
        for _, r in summary.loc[mask].iterrows():
            med_cache[r["metric"]] = r["median"]

        # Build category totals per operation using call counts
        cat_totals = {}  # (op, category) -> weighted cycles
        for op in profile_ops:
            calls = CALL_COUNTS.get(op, {})
            for func, count in calls.items():
                med = med_cache.get(func, np.nan)
                if np.isnan(med):
                    continue
                cat = CATEGORY_MAP.get(func, "Other")
                key = (op, cat)
                cat_totals[key] = cat_totals.get(key, 0) + med * count

        # Print header
        op_labels = [PROFILE_OP_LABEL[o] for o in profile_ops]
        hdr = f"{'Category':<12}"
        for lbl in op_labels:
            hdr += f" | {lbl:>12} | {'%':>6}"
        print(hdr)
        print("-" * len(hdr))

        # Compute totals per operation
        op_totals = {}
        for op in profile_ops:
            op_totals[op] = sum(
                cat_totals.get((op, cat), 0) for cat in CATEGORY_ORDER
            )

        for cat in CATEGORY_ORDER:
            line = f"{cat:<12}"
            for op in profile_ops:
                val = cat_totals.get((op, cat), 0)
                total = op_totals[op]
                pct = (val / total * 100) if total > 0 else 0.0
                line += f" | {fmt(val):>12} | {pct:>5.1f}%"
            print(line)

        # Total row
        line = f"{'Total':<12}"
        for op in profile_ops:
            total = op_totals[op]
            line += f" | {fmt(total):>12} | {'100.0%':>6}"
        print(line)

        # Compare estimated total with measured end-to-end
        print("\nEstimated vs Measured (optimized, median):")
        compare_map = {
            "keygen": ("keygen", "end2end"),
            "sign_attempt": ("sign", "per_attempt"),
            "verify": ("verify", "end2end"),
        }
        for op in profile_ops:
            est = op_totals[op]
            mop, mmet = compare_map[op]
            measured = get_stat(summary, param, "optimized", mop, mmet, "median")
            if not np.isnan(measured) and measured > 0:
                coverage = est / measured * 100
                print(
                    f"  {PROFILE_OP_LABEL[op]:<12}: estimated {fmt(est):>12} | "
                    f"measured {fmt(measured):>12} | coverage {coverage:.1f}%"
                )
            else:
                print(f"  {PROFILE_OP_LABEL[op]:<12}: estimated {fmt(est):>12} | measured N/A")


def save_summary_csv(summary, path):
    """Save the summary statistics to a CSV file."""
    cols = [
        "param", "build", "operation", "metric", "primary_set", "n",
        "median", "mean", "std", "min", "p5", "p95", "ci_lo", "ci_hi",
    ]
    out = summary[[c for c in cols if c in summary.columns]]
    out.to_csv(path, index=False, float_format="%.2f")
    print(f"\nSummary CSV saved to: {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Analyze NCC-Sign benchmark results and produce summary tables."
    )
    parser.add_argument(
        "csv_file",
        nargs="?",
        default="results_m1pro_final.csv",
        help="Path to the benchmark CSV file (default: results_m1pro_final.csv)",
    )
    parser.add_argument(
        "-o", "--output",
        default="summary_stats.csv",
        help="Output summary CSV filename (default: summary_stats.csv)",
    )
    args = parser.parse_args()

    df = load_csv(args.csv_file)
    print(f"Loaded {len(df)} rows from {args.csv_file}")
    print(f"Params: {sorted(df['param'].unique())}")
    print(f"Builds: {sorted(df['build'].unique())}")
    print(f"Operations: {sorted(df['operation'].unique())}")

    summary = build_summary(df)

    print_summary_tables(summary, df)
    print_profiling_tables(summary, df)
    save_summary_csv(summary, args.output)


if __name__ == "__main__":
    main()
