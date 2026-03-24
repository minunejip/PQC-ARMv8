# ARMv8/NEON Optimization of NCC-Sign

ARMv8/NEON-optimized implementation of the NCC-Sign lattice-based
digital signature scheme, targeting the NTT-friendly trinomial
parameter sets (NCC-Sign-1/3/5).

This repository accompanies the paper:

> **ARMv8/NEON Optimization of NCC-Sign for Mixed-Radix NTT:
> Cycle-Accurate Evaluation on Apple M1 Pro and Cortex-A72**
> Minwoo Lee, Minjoo Sim, Siwoo Eum, and Hwajeong Seo

## Repository Structure
```
crypto_sign/
├── NCC-Sign1/
│   ├── clean/          # Portable C reference (KPQClean baseline)
│   └── optimized/      # ARMv8/NEON-optimized implementation
├── NCC-Sign3/
│   ├── clean/
│   └── optimized/
├── NCC-Sign5/
│   ├── clean/
│   └── optimized/
└── sign_bench/
    ├── profile_bench.c     # Function-level profiling harness
    ├── microbench.c        # Montgomery vs Barrett microbenchmark
    ├── dudect_test.c       # Constant-time leakage detection (dudect)
    ├── dudect.h            # dudect library (adapted for macOS ARM)
    ├── run_20x.sh          # 20-run benchmark automation script
    └── parse_bench.py      # Result parsing and statistics
common/
├── fips202.c / fips202.h       # SHAKE/Keccak (scalar)
├── fips202x2.c / fips202x2.h   # SHAKE/Keccak 2-way NEON parallel
└── ...
```

## Build and Run

### Requirements

- ARMv8-A processor with NEON support (tested on Apple M1 Pro, Arm Cortex-A72)
- C compiler: Apple clang 14+ (macOS) or GCC 10+ (Linux)
- No external library dependencies

### Quick Start
```bash
# Build NCC-Sign-1 optimized
cd crypto_sign/NCC-Sign1/optimized
make

# Run correctness test
./KpqC_test

# Run benchmark (requires sudo on macOS for PMU access)
sudo ./KpqC_bench
```

### Building All Variants
```bash
# Build all 6 combinations (3 params × 2 builds)
for sign in NCC-Sign1 NCC-Sign3 NCC-Sign5; do
  for build in clean optimized; do
    cd crypto_sign/$sign/$build && make && cd ../../..
  done
done
```

### Cortex-A72 (Raspberry Pi 4)

The cycle-counting code automatically adapts to the platform:
- **macOS (Apple Silicon)**: Uses kperf/kpc PMU interface (requires sudo)
- **Linux (Cortex-A72)**: Uses perf_event_open (sudo not required if perf_event_paranoid ≤ 2)
```bash
# On Raspberry Pi 4 (Linux aarch64)
cd crypto_sign/NCC-Sign1/optimized
make
./KpqC_bench    # No sudo needed
```

## Benchmarking

### 20-Run Benchmark (Paper Methodology)
```bash
cd crypto_sign/sign_bench
# Runs all 6 combinations × 20 iterations each
# Outputs best-of-20, mean±std for each operation
sudo bash run_20x.sh
python3 parse_bench.py
```

### Function-Level Profiling
```bash
cd crypto_sign/sign_bench
sudo bash run_profile.sh
```

### Montgomery vs Barrett Microbenchmark
```bash
cd crypto_sign/sign_bench
make microbench
sudo ./microbench
```

### Constant-Time Testing (dudect)
```bash
cd crypto_sign/sign_bench
make dudect_test
sudo ./dudect_test    # Runs for several minutes per kernel
```

## Optimization Techniques

The optimized builds include the following ARMv8/NEON techniques:

1. **4-lane Montgomery multiply–reduce** using vqdmulhq_s32
2. **Centered modular reduction** (reduce32_vec)
3. **Fused stage-0 butterfly**
4. **Radix-2 multi-stage butterfly merging** — processes two NTT stages
   per memory pass, halving intermediate load/store traffic
5. **Stride-3 radix-3 vectorization** — exploits vld3q_s32/vst3q_s32 to
   fully vectorize small-len radix-3 stages (len=3, len=1) that would
   otherwise fall back to scalar code
6. **4-lane pointwise Montgomery multiplication**
7. **Two-way parallel hashing** (fips202x2) for secret-key sampling

All NEON kernels use standard ARMv8-A NEON instructions only (no SVE/SVE2)
and operate on 32-bit integer lanes (int32x4_t).

## Validation

Correctness is verified by the built-in test harness:
```bash
./KpqC_test
# Expected output: all sign/verify tests pass
```

The test generates key pairs, signs messages, and verifies signatures,
confirming that the optimized path produces bit-compatible results
with the reference implementation.

## Compile-Time Switches

The optimized builds enable NEON kernels via architecture detection
(`#ifdef __aarch64__`). On non-ARMv8 platforms, the code falls back
to the portable C reference path.

## License

See individual source files for license information.
The NCC-Sign reference code follows KPQClean conventions.
fips202x2 is based on code by Nguyen (CC0/public domain).
dudect is based on code by Reparaz et al. (public domain).
