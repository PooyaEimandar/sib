# SIB 🚀 powered by Rust 🦀 [![Build](https://github.com/PooyaEimandar/sib/actions/workflows/build.yml/badge.svg)](https://github.com/PooyaEimandar/sib/actions/workflows/build.yml)

**SIB** is a high-performance, secure, and cross-platform modules optimized for efficiency, scalability, and reliability.
it is designed for **real-time streaming**, **low-latency networking**, and **scalable HTTP services**.

> 🏷️ _"Sib" means **apple** in Persian (سیب)._

## ✨ Features

| Feature           | Description                                     |
| ----------------- | ----------------------------------------------- |
| `net-h1-server`   | Enable HTTP/1 server                            |
| `net-h2-server`   | Enable HTTP/2 server                            |
| `net-h3-server`   | Enable HTTP/3 server                            |
| `net-kafka-cli`   | Enable Kafka client                             |
| `net-ratelimiter` | Enable Ratelimiter service wrapper              |
| `net-ws-server`   | Enable WebSocket server                         |
| `net-wt-server`   | Enable WebTransport server                      |
| `db-fdb`          | FoundationDB client database + cache            |
| `rt-glommio`      | Enable glommio runtime for HTTP/2/3             |
| `rt-tokio`        | Enable tokio runtime for HTTP/2/3 and/or db-fdb |
| `rt-may`          | Enable may runtime for HTTP/1 and/or db-fdb     |
| `stm-sender`      | Real-time video/audio streamer                  |
| `stm-receiver`    | Real-time video/audio receiver                  |

## 📊 Benchmarks

### 🔬 [HTTP/1.1 TechEmpower Benchmark](https://github.com/TechEmpower/FrameworkBenchmarks/tree/master/frameworks/Rust/sib)

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

# ⚙️ Build note

You’ll need to set up the LLVM toolchain and related libraries first for using boringSSL.

## 📦 Prerequisites (Ubuntu/Debian)

```bash
sudo apt install -y cmake clang lld llvm libclang-dev
```

## 📦 Prerequisites (Windows)

Setup

- MSVC
- [CMake](https://cmake.org/download/)
- [Clang](https://github.com/llvm/llvm-project/releases)
- [NASM](https://www.nasm.us/)

## 📚 Documentation

- 📦 [Crate](https://crates.io/crates/sib)
- 📖 [Docs](https://docs.rs/sib)

## 📄 License

SIB is licensed under either of:

- [Apache License, Version 2.0](https://github.com/PooyaEimandar/sib/blob/main/LICENSE-APACHE)
- [MIT license](https://github.com/PooyaEimandar/sib/blob/main/LICENSE-MIT)

at your option.

## 🧭 [Roadmap](https://github.com/PooyaEimandar/sib/blob/main/ROADMAP.md)

## 🤝 [Contributing](https://github.com/PooyaEimandar/sib/blob/main/CONTRIBUTING.md)

## 📜 [Code of conduct](https://github.com/PooyaEimandar/sib/blob/main/CODE_OF_CONDUCT.md)

## 🔐 [Security](https://github.com/PooyaEimandar/sib/blob/main/SECURITY.md)
