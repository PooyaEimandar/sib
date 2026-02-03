# SIB 🚀 powered by Rust 🦀 [![Build](https://github.com/PooyaEimandar/sib/actions/workflows/build.yml/badge.svg)](https://github.com/PooyaEimandar/sib/actions/workflows/build.yml)

**SIB** is a high-performance, secure, and cross-platform modules optimized for efficiency, scalability, and reliability.
it is designed for **real-time streaming**, **low-latency networking**, and **scalable HTTP services**.

> 🏷️ _"Sib" means **apple** in Persian (سیب). Sib was the name of my first dog, a companion through the years._
<img src="https://raw.githubusercontent.com/PooyaEimandar/sib/main/sib.png" width="256" height="256" alt="Sib">


## ✨ Features

| Feature            | Description                                           |
| -------------------|-------------------------------------------------------|
| `mtls`             | Mutual TLS                                            |
| `net-h1-server`    | HTTP/1 server                                         |
| `net-h2-server`    | HTTP/2/1 server                                       |
| `net-h3-server`    | HTTP/3 server                                         |
| `net-kafka-cli`    | Kafka client                                          |
| `net-ratelimiter`  | Ratelimiter service wrapper                           |
| `net-ws-server`    | WebSocket server                                      |
| `net-wt-server`    | WebTransport server                                   |
| `db-fdb`           | FoundationDB client database + cache                  |
| `rt-glommio`       | glommio runtime                                       |
| `rt-tokio`         | tokio runtime                                         |
| `rt-may`           | may runtime                                           |
| `stm-udp-sender`   | UDP based Real-time video/audio streamer (SRT/RTP)    |
| `stm-udp-receiver` | UDP based Real-time video/audio receiver (SRT/RTP)    |
| `stm-webrtc-sender`| Web based Real-time video/audio/data streamer (WebRTC)|

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
