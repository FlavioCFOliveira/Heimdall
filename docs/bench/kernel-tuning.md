# Kernel tuning for accurate benchmarking

Accurate micro-benchmarks require a stable, low-noise hardware environment.
The following tuning steps are recommended before running any Heimdall
performance benchmarks.  All commands assume a Linux host with root access.

## CPU frequency scaling

Disable dynamic frequency scaling so that CPU frequency is constant throughout
the benchmark run.  Variable clock speeds introduce timing noise that can
exceed 10 % across samples.

```bash
echo performance | tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor
```

## Turbo boost

Disable Intel Turbo Boost (or AMD Precision Boost) to prevent burst-frequency
excursions from making short samples appear faster than steady-state throughput.

```bash
# Intel P-state driver:
echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo

# AMD (cpufreq driver):
echo 0 > /sys/devices/system/cpu/cpufreq/boost
```

## Transparent huge pages

Disable transparent huge pages (THP) to prevent page-promotion jitter from
contaminating allocation-sensitive benchmarks.

```bash
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag
```

## NUMA binding

Pin the benchmark process to a single NUMA node to eliminate remote-memory
latency.  Substitute `0` with the node hosting the cores under test.

```bash
numactl --cpunodebind=0 --membind=0 cargo bench -p heimdall-bench
```

## File descriptor limit

Increase the process file-descriptor limit to avoid spurious failures in
transport benchmarks.

```bash
ulimit -n 1048576
```

## IRQ affinity

Move interrupt handling away from the benchmarking cores to reduce inter-core
interference.  Example: reserve CPUs 0–3 for the OS and IRQs; run benchmarks
on CPUs 4–7.

```bash
for irq in /proc/irq/*/smp_affinity_list; do echo 0-3 > "$irq" 2>/dev/null || true; done
taskset -c 4-7 numactl --cpunodebind=0 --membind=0 cargo bench -p heimdall-bench
```

## Criterion configuration

Criterion's defaults are appropriate for most benchmarks:

| Parameter | Default | Rationale |
|---|---|---|
| Warm-up time | 3 s | Allows CPU frequency and branch-predictor state to stabilise. |
| Measurement time | 5 s | Accumulates enough samples to yield a stable mean. |
| Sample count | 100 | Provides sufficient data for the confidence-interval calculation. |
| Confidence level | 0.95 | Standard statistical threshold. |

Override only when justified.  For benchmarks whose setup cost significantly
exceeds their measurement cost, use `iter_batched` to amortise fixture
construction outside the timed region.

## Stability criterion

A benchmark run is considered stable when the coefficient of variation (CV =
standard deviation / mean) is below **2 %** across 100 samples.  Criterion
reports this as the "noise threshold" in its output.  If CV exceeds 2 %, repeat
the tuning steps above before recording a baseline.

## Baseline workflow

1. Run benchmarks on the `main` branch and save the baseline:

   ```bash
   cargo bench -p heimdall-bench -- --save-baseline main
   ```

2. Apply your change and run benchmarks against the saved baseline:

   ```bash
   cargo bench -p heimdall-bench -- --baseline main
   ```

3. Criterion will print a comparison table showing per-benchmark delta and
   confidence intervals.

4. Run the regression-gate binary to enforce the 5 % threshold automatically:

   ```bash
   # Point to the criterion estimates.json files for a specific benchmark.
   heimdall-bench-compare \
     target/criterion/<bench>/main/estimates.json \
     target/criterion/<bench>/new/estimates.json
   ```
