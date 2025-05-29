# SIB [![Build](https://github.com/PooyaEimandar/sib/actions/workflows/build.yml/badge.svg)](https://github.com/PooyaEimandar/sib/actions/workflows/build.yml)

A high-performance, secure, and cross-platform modules optimized for efficiency, scalability, and reliability.

## 🔬 [HTTP 1.1 TechEmpower Benchmark](https://github.com/PooyaEimandar/sib/techempower)

### 📈 Plaintext Benchmark Summary

**Environment:**

- 🧠 12-core CPU
- 🧮 32 GB RAM
- 🐳 Docker container
- ⚙️ `target-cpu=native` on Apple Macbook Pro M2 Max 2023

| Concurrency | Requests/sec  | Latency (avg) | Transfer/sec |
| ----------- | ------------- | ------------- | ------------ |
| 8           | 105,598       | 75.70 µs      | 12.89 MB/s   |
| 512         | 840,036       | 0.99 ms       | 102.54 MB/s  |
| 256         | 5,106,291     | 1.06 ms       | 623.33 MB/s  |
| 1024        | **6,112,892** | 1.71 ms       | 746.20 MB/s  |
| 4096        | 5,890,631     | 5.11 ms       | 719.07 MB/s  |
| 16384       | 5,038,547     | 19.11 ms      | 615.06 MB/s  |

## 🦀 Powered by Rust

Sib's HTTP 1.1 uses:

- [`may`](https://github.com/Xudong-Huang/may_minihttp) for coroutine scheduling.
- [`bytes`](https://github.com/tokio-rs/bytes) for zero-copy HTTP parser.
- [`mimalloc`](https://github.com/microsoft/mimalloc) a compact general purpose allocator with excellent performance.
