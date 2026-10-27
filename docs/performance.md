# Performance

## Targets

| Operation | Target |
|---|---|
| Encryption | 200-500 MB/s (parallel) |
| Decryption | 150-300 MB/s |
| Memory footprint | Constant: peak Go heap of about 25-45 MB to archive or extract, independent of file and archive size (archiving files of 64 MB or more memory-maps them, so RSS also counts reclaimable page cache) |
| Archive overhead | < 5% (padding + headers) |

## Benchmark against zip

![Benchmark results](https://raw.githubusercontent.com/iamvirul/sarc/master/benchmarks/benchmark_results.png)

Every pull request runs a benchmark comparing sarc's archive and extract throughput with
zip, on 1 GB of random data and a 512 MB 3D mesh. The chart is committed to
`benchmarks/benchmark_results.png` and the results are posted on the pull request.

The free `ubuntu-latest` runner has room for test files of up to 5 GB (14 GB of disk); a
16-core runner (Team or Enterprise plans) allows 10 GB and more. Set `TEST_FILE_GB` in
`.github/workflows/benchmark.yml` and switch the runner to change it.

Go benchmarks of the building blocks:

```bash
go test -bench=. -benchmem ./benchmarks/...
```

## Archive size

Compared with zip (default settings) on Go source trees:

| Tree | zip | sarc per-file (auto) | sarc `--solid` | sarc `--solid --compress-level 19` |
|---|---|---|---|---|
| `net/http` (113 files) | 616K | 888K | 557K (-10%) | 474K (-23%) |
| `runtime` (1088 files) | 4358K | 6721K | 3453K (-21%) | 2979K (-32%) |
| `cmd/go` (1496 files) | 1883K | 4933K | 1244K (-34%) | 1062K (-44%) |

Per-file mode stays larger than zip on small-file trees because every entry carries about
2.2 KB of random anti-deduplication padding; solid mode pays that once per group.
