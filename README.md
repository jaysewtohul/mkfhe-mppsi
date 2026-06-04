# MK-FHE MP-PSI

This repository contains the proof-of-concept implementation of **Multi-Key Fully Homomorphic Encryption for Multi-Party Private Set Intersection**, as described in our accompanying paper.

By mapping datasets to boolean vectors and exploiting the Single Instruction, Multiple Data (SIMD) batching capabilities of the BGV scheme, this implementation reduces the intersection logic strictly to homomorphic additions and scalar multiplications. This achieves a zero-depth multiplicative circuit, neutralizing the standard computational bottlenecks of FHE.

## Architecture

* **Cryptographic Backend:** [Lattigo v6](https://github.com/tuneinsight/lattigo) (Go).
* **Encryption Scheme:** Brakerski-Gentry-Vaikuntanathan (BGV) in a Multi-Key (MK) setting.
* **Network Topology:** Star topology utilizing a centralized Leader for homomorphic aggregation.
* **Post-Quantum Security:** Parameters configured for >256-bit post-quantum security against known lattice attacks ($N=16384$, $\log_2(q)=216$).

## Repository Structure

* `main.go`: Functional proof-of-concept. It demonstrates the correctness of the zero-depth masking algorithm and outputs part of the intersection.
* `benchmark.go`: Benchmarking suite. It scales the protocol across varying network sizes ($n$) and database sizes ($|D|$), outputting the empirical telemetry (Time, Bandwidth, and Peak Memory) formatted as LaTeX tables.

## Prerequisites

To run this code locally, you must have the Go toolchain installed (version 1.20 or higher is recommended).

```bash
# Clone the repository
git clone [https://github.com/YourUsername/mkfhe-mppsi.git](https://github.com/YourUsername/mkfhe-mppsi.git)
cd mkfhe-mppsi

# Download dependencies (Lattigo)
go mod tidy
```

# Usage and Reproducibility
## Functional Verification
To verify the cryptographic correctness of the intersection logic:
```bash
go run main.go
```
This will simulate $n=5$ participants with a domain of 1,000,000 elements, compute the multi-key joint ciphertext, generate distributed decryption shares, and print a sample of the underlying plaintext array.

## Academic Benchmarks
To reproduce the empirical metrics presented in Section 6 of the paper:
```bash
go run benchmark.go
```
Note: The benchmarking suite simulates the full cryptographic overhead of up to 50 participants locally. Ensure your host machine has sufficient memory (16GB+ recommended) and minimal background CPU load to prevent memory thrashing.

# Performance Summary
Our experimental results establish that, under this architecture, CPU processing power is no longer the primary bottleneck for FHE-based MP-PSI. The protocol successfully aggregates and masks a 1,000,000-item database across 50 distinct participants in under 2.5 seconds (unoptimized, single-threaded).

However, the communication complexity scales strictly linearly. Processing a 10,000,000-element domain for 10 participants results in a multi-key joint ciphertext broadcast exceeding 2.5 GB. We conclude that optimizing network bandwidth and ciphertext compression are the critical frontiers for future MK-FHE deployments.

# License
This project is licensed under the MIT License - see the LICENSE file for details.
