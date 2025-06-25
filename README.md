# SIB 🚀 powered by Rust 🦀 [![Build](https://github.com/PooyaEimandar/sib/actions/workflows/build.yml/badge.svg)](https://github.com/PooyaEimandar/sib/actions/workflows/build.yml)

**SIB** is a high-performance, secure, and cross-platform modules optimized for efficiency, scalability, and reliability.
it is designed for **real-time networking**, **low-latency streaming**, and **scalable HTTP services**.

## ✨ Features

| Feature          | Description                                                |
| ---------------- | ---------------------------------------------------------- |
| `net-h1-server`  | Enable HTTP/1.1 server with coroutine concurrency          |
| `net-h3-server`  | Enable HTTP/3 QUIC-based server with coroutine concurrency |
| `db-fdb`         | FoundationDB bindings (requires `libfdb_c`) on macOS/Linux |
| `stm-sender`     | Real-time video/audio streamer server                      |
| `stm-receiver`   | Real-time video/audio receiver                             |
| `sys-boring-ssl` | BoringSSL backend for secure networking                    |

## 📊 Benchmarks

### 🔬 [HTTP 1.1 TechEmpower Plaintext Benchmark](https://github.com/PooyaEimandar/FrameworkBenchmarks/tree/master/frameworks/Rust/sib)

**Environment:**

- 🧠 12-core CPU
- 🧮 32 GB RAM
- 🐳 Docker container
- ⚙️ `target-cpu=native` on Apple Macbook Pro M2 Max 2023
- Sib HTTP1.1 uses:
  - [`may`](https://github.com/Xudong-Huang/may) for coroutine scheduling.
  - [`bytes`](https://github.com/tokio-rs/bytes) for zero-copy HTTP parser.
  - [`mimalloc`](https://github.com/microsoft/mimalloc) a compact general purpose allocator with excellent performance.

| Concurrency | Requests/sec  | Latency (avg) | Transfer/sec |
| ----------- | ------------- | ------------- | ------------ |
| 8           | 105,598       | 75.70 µs      | 12.89 MB/s   |
| 512         | 840,036       | 0.99 ms       | 102.54 MB/s  |
| 256         | 5,106,291     | 1.06 ms       | 623.33 MB/s  |
| 1024        | **6,112,892** | 1.71 ms       | 746.20 MB/s  |
| 4096        | 5,890,631     | 5.11 ms       | 719.07 MB/s  |
| 16384       | 5,038,547     | 19.11 ms      | 615.06 MB/s  |

## 📚 Documentation

- 📦 [Crate](https://crates.io/crates/sib)
- 📖 [Docs](https://docs.rs/sib)
- 🧪 [Benchmarks: TechEmpower](https://github.com/TechEmpower/FrameworkBenchmarks)

## 📄 License

SIB is licensed under either of:

- [Apache License, Version 2.0](https://github.com/PooyaEimandar/sib/blob/main/LICENSE-APACHE)
- [MIT license](https://github.com/PooyaEimandar/sib/blob/main/LICENSE-MIT)

at your option.
