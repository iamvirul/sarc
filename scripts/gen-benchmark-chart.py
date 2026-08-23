#!/usr/bin/env python3
# Copyright (c) 2026 iamvirul. All rights reserved.
# Use of this source code is governed by the MIT license.
#
# Reads benchmark env vars and writes benchmarks/benchmark_results.png.
# Required env: SARC_ARCHIVE_MS, ZIP_ARCHIVE_MS, SARC_EXTRACT_MS, ZIP_EXTRACT_MS, FILE_SIZE_GB
# Required env (3D mesh dataset): MESH_SARC_ARCHIVE_MS, MESH_ZIP_ARCHIVE_MS,
#   MESH_SARC_EXTRACT_MS, MESH_ZIP_EXTRACT_MS, MESH_FILE_MB

import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

def get_env(key):
    val = os.environ.get(key)
    if val is None:
        print(f"ERROR: missing env var {key}", file=sys.stderr)
        sys.exit(1)
    return float(val)

def ms_to_mbs(ms, total_mb):
    """Convert milliseconds to MB/s given the dataset's total size in MB."""
    if ms <= 0:
        return 0
    return total_mb / (ms / 1000)

def plot_dataset(axes_row, title, sarc_archive_ms, zip_archive_ms, sarc_extract_ms, zip_extract_ms, total_mb):
    sarc_vals = [ms_to_mbs(sarc_archive_ms, total_mb), ms_to_mbs(sarc_extract_ms, total_mb)]
    zip_vals  = [ms_to_mbs(zip_archive_ms, total_mb),  ms_to_mbs(zip_extract_ms, total_mb)]
    sarc_times = [sarc_archive_ms / 1000, sarc_extract_ms / 1000]
    zip_times  = [zip_archive_ms  / 1000, zip_extract_ms  / 1000]

    labels = ["Archive", "Extract"]
    x = np.arange(len(labels))
    bar_width = 0.32

    ax = axes_row[0]
    b1 = ax.bar(x - bar_width / 2, sarc_vals, bar_width, label="sarc", color="#2563EB")
    b2 = ax.bar(x + bar_width / 2, zip_vals,  bar_width, label="zip",  color="#6B7280")
    ax.set_ylabel("Throughput (MB/s)")
    ax.set_title(f"{title} — Throughput")
    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.legend()
    ax.bar_label(b1, fmt="%.0f", padding=3, fontsize=9)
    ax.bar_label(b2, fmt="%.0f", padding=3, fontsize=9)
    ax.set_ylim(0, max(sarc_vals + zip_vals) * 1.3 or 1)

    ax2 = axes_row[1]
    b3 = ax2.bar(x - bar_width / 2, sarc_times, bar_width, label="sarc", color="#2563EB")
    b4 = ax2.bar(x + bar_width / 2, zip_times,  bar_width, label="zip",  color="#6B7280")
    ax2.set_ylabel("Elapsed time (s)")
    ax2.set_title(f"{title} — Elapsed Time")
    ax2.set_xticks(x)
    ax2.set_xticklabels(labels)
    ax2.legend()
    ax2.bar_label(b3, fmt="%.1f s", padding=3, fontsize=9)
    ax2.bar_label(b4, fmt="%.1f s", padding=3, fontsize=9)
    ax2.set_ylim(0, max(sarc_times + zip_times) * 1.3 or 1)

file_size_gb = float(os.environ.get("FILE_SIZE_GB", "1"))
mesh_file_mb = float(os.environ.get("MESH_FILE_MB", "0"))
has_mesh = mesh_file_mb > 0

fig, axes = plt.subplots(2 if has_mesh else 1, 2, figsize=(12, 10 if has_mesh else 5))
fig.suptitle("sarc vs zip benchmark", fontsize=14, fontweight="bold", y=1.02)

random_axes = axes[0] if has_mesh else axes
plot_dataset(
    random_axes,
    f"Random data ({file_size_gb:.0f} GB)",
    get_env("SARC_ARCHIVE_MS"),
    get_env("ZIP_ARCHIVE_MS"),
    get_env("SARC_EXTRACT_MS"),
    get_env("ZIP_EXTRACT_MS"),
    file_size_gb * 1024,
)

if has_mesh:
    plot_dataset(
        axes[1],
        f"3D mesh, binary STL ({mesh_file_mb:.0f} MB)",
        get_env("MESH_SARC_ARCHIVE_MS"),
        get_env("MESH_ZIP_ARCHIVE_MS"),
        get_env("MESH_SARC_EXTRACT_MS"),
        get_env("MESH_ZIP_EXTRACT_MS"),
        mesh_file_mb,
    )

fig.tight_layout()

out_path = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "benchmark_results.png")
out_path = os.path.normpath(out_path)
os.makedirs(os.path.dirname(out_path), exist_ok=True)
fig.savefig(out_path, dpi=150, bbox_inches="tight")
print(f"chart saved: {out_path}")
