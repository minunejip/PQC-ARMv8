SNOVA ARMv8 Optimized Implementation
Overview
This repository contains an optimized implementation of the SNOVA post-quantum digital signature scheme targeting ARMv8 architectures with NEON SIMD acceleration.

The implementation includes:

Rank-specific SIMD kernels for efficient matrix operations

Cycle-level benchmarking modules

Support for both keypair generation, signing, and verification

Build Instructions
Requirements

GCC (version 9 or above recommended)

Make utility

macOS (tested on macOS 13.3 with Apple M2) or other ARMv8 platforms

Build

bash

make
This will compile the executable named main.

Running Benchmarks
Run the compiled binary:

bash

./main
This will execute:

Correctness tests (signature generation and verification)

Performance benchmarks (test_speed), printing average cycle counts over 1,000,000 iterations

Test Vectors
During execution, the test_sign() function outputs:

Private/public key seeds

Digest values

Generated signatures

These outputs can be used as test vectors for kernel validation.

Dependencies
This implementation has no external library dependencies (e.g., OpenSSL). All required functions are included in this repository.

Notes
Tested on Apple M2 under macOS 13.3

Compilation flags and environment are detailed in the Makefile and manuscript Section 4.2
