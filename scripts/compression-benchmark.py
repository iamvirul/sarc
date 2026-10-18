#!/usr/bin/env python3
# Copyright (c) 2026 iamvirul. All rights reserved.
# Use of this source code is governed by the MIT license.
#
# Benchmarks sarc compression modes against zip on compressible and incompressible data,
# verifies every extraction byte for byte, and writes Markdown and JSON reports.
#
# Usage: compression-benchmark.py --sarc ./sarc-bin --work DIR --markdown OUT.md --json OUT.json
# Env:   LOG_MB (default 256), JSON_MB (default 128), RANDOM_MB (default 256),
#        GOROOT_SRC (default: `go env GOROOT`/src)
#
# Exits non-zero if any tool fails or any extracted file differs from its original.

import argparse
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time

PASSWORD = "compression-benchmark-password"
SOURCE_TREES = ("net/http", "runtime", "cmd/go")
SEED = 20261018


def env_int(name, default):
    value = os.environ.get(name, str(default))
    try:
        parsed = int(value)
    except ValueError:
        sys.exit(f"ERROR: {name} must be an integer, got {value!r}")
    if parsed <= 0:
        sys.exit(f"ERROR: {name} must be positive, got {parsed}")
    return parsed


def run(args, cwd=None):
    """Run a command, failing the benchmark with its output if it exits non-zero."""
    result = subprocess.run(args, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        sys.exit(f"ERROR: {' '.join(args[:3])}... exited {result.returncode}\n{result.stdout}\n{result.stderr}")
    return result


def timed(args, cwd=None):
    start = time.perf_counter()
    run(args, cwd=cwd)
    return time.perf_counter() - start


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def flatten_tree(src_root, dest):
    """Copy every regular file under src_root into dest with a unique flat name.

    sarc stores base names only, so duplicate names in different directories would
    overwrite each other on extraction; flattening gives zip and sarc identical inputs.
    """
    os.makedirs(dest)
    for dirpath, _, filenames in os.walk(src_root):
        for name in filenames:
            src = os.path.join(dirpath, name)
            if not os.path.isfile(src) or os.path.islink(src):
                continue
            rel = os.path.relpath(src, src_root).replace(os.sep, "__")
            shutil.copyfile(src, os.path.join(dest, rel))


def write_logs(path, megabytes, rng):
    statuses = (200, 200, 200, 200, 201, 304, 404, 500)
    routes = ("/api/users", "/api/orders", "/api/items", "/healthz", "/api/search")
    target = megabytes << 20
    with open(path, "w") as f:
        written, i = 0, 0
        while written < target:
            line = (f"2026-10-18T{(i // 3600) % 24:02d}:{(i // 60) % 60:02d}:{i % 60:02d}Z level=info "
                    f"service=api trace_id={rng.getrandbits(64):016x} method=GET path={rng.choice(routes)} "
                    f"status={rng.choice(statuses)} duration_ms={rng.randint(1, 900)}\n")
            f.write(line)
            written += len(line)
            i += 1


def write_json(path, megabytes, rng):
    target = megabytes << 20
    with open(path, "w") as f:
        f.write("[")
        written, i = 1, 0
        while written < target:
            record = json.dumps({
                "id": i, "name": f"user{i}", "email": f"user{i}@example.com",
                "active": i % 3 == 0, "score": round(rng.random(), 6),
                "tags": ["alpha", "beta", "gamma"][: i % 4],
            })
            chunk = ("," if i else "") + record
            f.write(chunk)
            written += len(chunk)
            i += 1
        f.write("]")


def write_random(path, megabytes, rng):
    with open(path, "wb") as f:
        for _ in range(megabytes):
            f.write(rng.randbytes(1 << 20))


def dataset_files(directory):
    return sorted(os.path.join(directory, n) for n in os.listdir(directory))


def verify(originals, out_dir):
    """Fail unless out_dir holds exactly the original files, byte for byte."""
    expected = {os.path.basename(p): sha256_file(p) for p in originals}
    extracted = sorted(os.listdir(out_dir))
    if extracted != sorted(expected):
        sys.exit(f"ERROR: extracted file set differs in {out_dir}: {len(extracted)} vs {len(expected)} files")
    for name, digest in expected.items():
        if sha256_file(os.path.join(out_dir, name)) != digest:
            sys.exit(f"ERROR: content mismatch for {name} in {out_dir}")


def bench_zip(files, src_dir, work):
    archive = os.path.join(work, "bench.zip")
    out_dir = os.path.join(work, "zip-out")
    archive_s = timed(["zip", "-q", "-r", archive, "."], cwd=src_dir)
    size = os.path.getsize(archive)
    extract_s = timed(["unzip", "-q", archive, "-d", out_dir])
    verify(files, out_dir)
    os.remove(archive)
    shutil.rmtree(out_dir)
    return {"tool": "zip", "size": size, "archive_s": archive_s, "extract_s": extract_s}


def bench_sarc(sarc, label, flags, files, work):
    archive = os.path.join(work, "bench.sarc")
    out_dir = os.path.join(work, "sarc-out")
    archive_s = timed([sarc, "archive", "-p", PASSWORD, "-o", archive, *flags, *files])
    size = os.path.getsize(archive)
    extract_s = timed([sarc, "extract", "-p", PASSWORD, "-a", archive, "-o", out_dir])
    verify(files, out_dir)
    os.remove(archive)
    shutil.rmtree(out_dir)
    return {"tool": label, "size": size, "archive_s": archive_s, "extract_s": extract_s}


SINGLE_FILE_MODES = (
    ("sarc --no-compress", ["--no-compress"]),
    ("sarc (auto)", []),
)
TREE_MODES = SINGLE_FILE_MODES + (
    ("sarc --solid", ["--solid"]),
    ("sarc --solid --compress-level 19", ["--solid", "--compress-level", "19"]),
)


def human_size(n):
    for unit, scale in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
        if n >= scale:
            return f"{n / scale:.1f} {unit}"
    return f"{n} B"


def markdown_report(results):
    lines = [
        "<!-- sarc-compression-benchmark -->",
        "## Compression benchmark: sarc vs zip",
        "",
        "Every extraction is verified byte for byte. Sizes include sarc's per-entry "
        "anti-deduplication padding; `vs zip` compares archive size with `zip -r` (DEFLATE).",
        "",
    ]
    for ds in results:
        zip_size = next(r["size"] for r in ds["runs"] if r["tool"] == "zip")
        lines += [
            f"### {ds['name']} ({ds['files']} file{'s' if ds['files'] != 1 else ''}, {human_size(ds['bytes'])})",
            "",
            "| Tool | Archive size | vs zip | Archive time | Extract time |",
            "|---|---|---|---|---|",
        ]
        best = min(r["size"] for r in ds["runs"])
        for r in ds["runs"]:
            delta = "-" if r["tool"] == "zip" else f"{(r['size'] / zip_size - 1) * 100:+.0f}%"
            size = human_size(r["size"])
            if r["size"] == best:
                size = f"**{size}**"
            lines.append(f"| {r['tool']} | {size} | {delta} | {r['archive_s']:.2f} s | {r['extract_s']:.2f} s |")
        lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sarc", required=True, help="path to the sarc binary")
    parser.add_argument("--work", required=True, help="empty scratch directory")
    parser.add_argument("--markdown", required=True, help="Markdown report output path")
    parser.add_argument("--json", required=True, help="JSON report output path")
    args = parser.parse_args()

    sarc = os.path.abspath(args.sarc)
    if not os.access(sarc, os.X_OK):
        sys.exit(f"ERROR: sarc binary not executable: {sarc}")
    for tool in ("zip", "unzip"):
        if shutil.which(tool) is None:
            sys.exit(f"ERROR: {tool} not found on PATH")
    work = os.path.abspath(args.work)
    os.makedirs(work, exist_ok=True)
    if os.listdir(work):
        sys.exit(f"ERROR: work directory must be empty: {work}")

    goroot_src = os.environ.get("GOROOT_SRC") or os.path.join(
        run(["go", "env", "GOROOT"]).stdout.strip(), "src")
    rng = random.Random(SEED)

    datasets = []
    for tree in SOURCE_TREES:
        src = os.path.join(goroot_src, tree)
        if not os.path.isdir(src):
            sys.exit(f"ERROR: source tree not found: {src}")
        dest = os.path.join(work, "data", tree.replace("/", "_"))
        flatten_tree(src, dest)
        datasets.append((f"Go source: {tree}", dest, TREE_MODES))
    for name, writer, megabytes, filename in (
        ("Server logs", write_logs, env_int("LOG_MB", 256), "app.log"),
        ("JSON records", write_json, env_int("JSON_MB", 128), "records.json"),
        ("Random data (incompressible)", write_random, env_int("RANDOM_MB", 256), "random.bin"),
    ):
        dest = os.path.join(work, "data", filename.split(".")[0])
        os.makedirs(dest)
        writer(os.path.join(dest, filename), megabytes, rng)
        datasets.append((name, dest, SINGLE_FILE_MODES))

    results = []
    for name, directory, modes in datasets:
        files = dataset_files(directory)
        runs = [bench_zip(files, directory, work)]
        for label, flags in modes:
            runs.append(bench_sarc(sarc, label, flags, files, work))
        results.append({"name": name, "files": len(files), "bytes": sum(os.path.getsize(f) for f in files), "runs": runs})
        print(f"done: {name}", flush=True)

    with open(args.json, "w") as f:
        json.dump(results, f, indent=2)
    with open(args.markdown, "w") as f:
        f.write(markdown_report(results))
    print(markdown_report(results))


if __name__ == "__main__":
    main()
