#!/usr/bin/env python3
# Copyright (c) 2026 iamvirul. All rights reserved.
# Use of this source code is governed by the MIT license.
#
# Reads benchmark env vars and writes benchmarks/benchmark_results.png.
# Required env: SARC_ARCHIVE_MS, ZIP_ARCHIVE_MS, SARC_EXTRACT_MS, ZIP_EXTRACT_MS, FILE_SIZE_GB

import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np

def get_env(key):
    val = os.environ.get(key)
    if val is None:
        print(f"ERROR: missing env var {key}", file=sys.stderr)
        sys.exit(1)
    return float(val)

sarc_archive_ms = get_env("SARC_ARCHIVE_MS")
zip_archive_ms  = get_env("ZIP_ARCHIVE_MS")
sarc_extract_ms = get_env("SARC_EXTRACT_MS")
zip_extract_ms  = get_env("ZIP_EXTRACT_MS")
file_size_gb    = float(os.environ.get("FILE_SIZE_GB", "1"))

def ms_to_mbs(ms):
    """Convert milliseconds to MB/s given FILE_SIZE_GB."""
    if ms <= 0:
        return 0
    return (file_size_gb * 1024) / (ms / 1000)

sarc_archive_mbs = ms_to_mbs(sarc_archive_ms)
zip_archive_mbs  = ms_to_mbs(zip_archive_ms)
sarc_extract_mbs = ms_to_mbs(sarc_extract_ms)
zip_extract_mbs  = ms_to_mbs(zip_extract_ms)

labels = ["Archive", "Extract"]
sarc_vals = [sarc_archive_mbs, sarc_extract_mbs]
zip_vals  = [zip_archive_mbs,  zip_extract_mbs]

x = np.arange(len(labels))
bar_width = 0.32

fig, axes = plt.subplots(1, 2, figsize=(12, 5))
fig.suptitle(
    f"sarc vs zip — {file_size_gb:.0f} GB random data benchmark",
    fontsize=14, fontweight="bold", y=1.02
)

# Left: throughput (MB/s)
ax = axes[0]
b1 = ax.bar(x - bar_width / 2, sarc_vals, bar_width, label="sarc", color="#2563EB")
b2 = ax.bar(x + bar_width / 2, zip_vals,  bar_width, label="zip",  color="#6B7280")
ax.set_ylabel("Throughput (MB/s)")
ax.set_title("Throughput")
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.legend()
ax.bar_label(b1, fmt="%.0f", padding=3, fontsize=9)
ax.bar_label(b2, fmt="%.0f", padding=3, fontsize=9)
ax.set_ylim(0, max(sarc_vals + zip_vals) * 1.3 or 1)

# Right: elapsed time (s)
sarc_times = [sarc_archive_ms / 1000, sarc_extract_ms / 1000]
zip_times  = [zip_archive_ms  / 1000, zip_extract_ms  / 1000]
ax2 = axes[1]
b3 = ax2.bar(x - bar_width / 2, sarc_times, bar_width, label="sarc", color="#2563EB")
b4 = ax2.bar(x + bar_width / 2, zip_times,  bar_width, label="zip",  color="#6B7280")
ax2.set_ylabel("Elapsed time (s)")
ax2.set_title("Elapsed Time")
ax2.set_xticks(x)
ax2.set_xticklabels(labels)
ax2.legend()
ax2.bar_label(b3, fmt="%.1f s", padding=3, fontsize=9)
ax2.bar_label(b4, fmt="%.1f s", padding=3, fontsize=9)
ax2.set_ylim(0, max(sarc_times + zip_times) * 1.3 or 1)

fig.tight_layout()

out_path = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "benchmark_results.png")
out_path = os.path.normpath(out_path)
os.makedirs(os.path.dirname(out_path), exist_ok=True)
fig.savefig(out_path, dpi=150, bbox_inches="tight")
print(f"chart saved: {out_path}")
