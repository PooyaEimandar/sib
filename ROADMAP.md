# SIB Roadmap

## Vision
SIB aims to become a next-generation, high-performance Rust-based networking runtime for cloud-native and edge computing environments — combining the scalability, the performance, and the safety.

---

## Core Objectives
1. **Performance** — achieve best-in-class latency and throughput for HTTP/1.1, HTTP/2, HTTP/3, WebSocket and WebTransport.
2. **Security** — implement strong cryptographic and isolation and sandboxed runtimes.
3. **Observability** — provide deep metrics, traces, and logs for large-scale deployments.
4. **Extensibility** — support dynamic modules via WASM without recompilation.
5. **Real-Time Streaming** — enable ultra-low-latency streaming and real-time communication.

---

## Milestone 1 : Core features
✅ Target: Production ready

- [x] HTTP1.1 with boringSSL and may
- [x] HTTP2 with rustls (glommio/tokio runtime)
- [x] HTTP3 with rustls (glommio/tokio runtime)
- [x] gstreamer
- [x] Static file server
- [x] Integration with io_uring
- [x] Websocket server
- [x] Webtransport server
- [x] Auto benchmark mode (TechEmpower-compatible)
- [x] ACID cache over FoundationDB
- [x] Ratelimit per ip/session
- [ ] Integration with ClickHouse

## Milestone 2 : Observability & Security
✅ Target: CNCF Sandbox readiness

- [ ] Prometheus exporter (`/metrics`)
- [ ] Integration with OpenTelemetry for metrics, traces, and logs
- [ ] `sibctl` CLI for local development and benchmarking
- [ ] Certificate hot reload
- [ ] gRPC over HTTP/2
- [ ] gRPC over HTTP/3
- [ ] Developer documentation site

---

## Milestone 2 : Scalability & Federation
✅ Target: Production & multi-node clustering

- [ ] RAFT for scaling
- [ ] Plugin API via WASM
- [ ] `/healthz`, `/readyz`, `/livez` endpoints
- [ ] Distributed clustering using Redpanda or FoundationDB coordination
- [ ] Session-aware load balancing
- [ ] Dynamic rate limiting with feedback loop
- [ ] Operator for auto-scaling and rolling updates
- [ ] Dashboard & REST Admin API


---

## Long-Term Vision
- Establish SIB as a **CNCF Incubating project**.
