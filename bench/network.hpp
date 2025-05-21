/*
  Mozilla Public License 2.0 (MPL-2.0)

  This file is part of the "https://github.com/PooyaEimandar/sib" project, which is licensed under
  the MPL-2.0. You can obtain a copy of the license at: https://opensource.org/licenses/MPL-2.0

  The MPL-2.0 allows you to use, modify, and distribute this file under certain conditions.
  The source code may be modified and distributed, provided that you retain the same license
  and include a copy of this notice when redistributing the code.

  This project was created by Pooya Eimandar.

  For more information on the terms of this license, please refer to the official MPL-2.0
  documentation.

  SPDX-License-Identifier: MPL-2.0
*/

#ifdef SIB_NET_PROXYGEN

#pragma once

#include <folly/Benchmark.h>

#include <folly/net/NetworkSocket.h>
#include <proxygen/lib/http/HTTPMessage.h>
#include <proxygen/lib/http/session/HTTPTransaction.h>

#include <sib/network/s_proxygen_server.hpp>

using namespace sib::network::http;

constexpr auto MAX_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB
constexpr auto sleep_duration = std::chrono::seconds(3);

struct hello_handler : public proxygen::HTTPTransaction::Handler {
  virtual void onHeadersComplete(
    std::unique_ptr<proxygen::HTTPMessage> p_headers) noexcept override {
    if (p_headers->getMethod() == proxygen::HTTPMethod::GET) {
      constexpr auto* plain_text = "text/plain";
      constexpr auto* body = "Hello from Sib!";
      constexpr auto* body_len_str = "15";
      static const auto body_len = strlen(body);

      proxygen::HTTPMessage response;
      response.setStatusCode(200);
      response.setStatusMessage("OK");
      response.setIsChunked(false);
      response.setWantsKeepalive(true);

      auto& headers = response.getHeaders();
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_TYPE, plain_text);
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_LENGTH, body_len_str);

      _txn->sendHeaders(response);

      _txn->sendBody(std::move(folly::IOBuf::wrapBuffer(body, body_len)));
      _txn->sendEOM();
    }
  }
  virtual void onBody([[maybe_unused]] std::unique_ptr<folly::IOBuf> p_chain) noexcept override {}
  virtual void onTrailers(
    [[maybe_unused]] std::unique_ptr<proxygen::HTTPHeaders> p_trailers) noexcept override {}
  virtual void onUpgrade([[maybe_unused]] proxygen::UpgradeProtocol p_protocol) noexcept override {}
  virtual void onError(const proxygen::HTTPException& p_error) noexcept override {}
  virtual void onEgressPaused() noexcept override {}
  virtual void onEgressResumed() noexcept override {}
  void setTransaction(proxygen::HTTPTransaction* p_txn) noexcept override { _txn = p_txn; }
  void detachTransaction() noexcept override { delete this; }
  void onEOM() noexcept override {}
  proxygen::HTTPTransaction* _txn{nullptr};
};

auto create_socket_opt() {
  using ApplyPos = folly::SocketOptionKey::ApplyPos;
  folly::SocketOptionMap socket_opt{};
  // Enable SO_REUSEADDR, this is important for the server to be able to restart quickly
  socket_opt.emplace(
    folly::SocketOptionKey{SOL_SOCKET, SO_REUSEADDR, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{1});

  // Disable Nagle (reduce latency)
  socket_opt.emplace(
    folly::SocketOptionKey{IPPROTO_TCP, TCP_NODELAY, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{1});
  socket_opt.emplace(
    folly::SocketOptionKey{IPPROTO_TCP, TCP_NODELAY, ApplyPos::POST_BIND},
    folly::SocketOptionValue{1});

  // Increase socket buffers (avoid drops under load)
  socket_opt.emplace(
    folly::SocketOptionKey{SOL_SOCKET, SO_RCVBUF, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{MAX_BUFFER_SIZE});
  socket_opt.emplace(
    folly::SocketOptionKey{SOL_SOCKET, SO_SNDBUF, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{MAX_BUFFER_SIZE});

// Linux only TCP fast open for reducing handshake overhead
#ifdef __linux__
  socket_opt.emplace(
    folly::SocketOptionKey{SOL_SOCKET, SO_REUSEPORT, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{1});
  socket_opt.emplace(
    folly::SocketOptionKey{IPPROTO_TCP, TCP_FASTOPEN, ApplyPos::PRE_BIND},
    folly::SocketOptionValue{1000} // Queue length for TFO
  );
#endif

  return socket_opt;
}

BENCHMARK(s_h1_proxygen_server_start_stop) {
  const auto num_threads = std::thread::hardware_concurrency();

  proxygen::HTTPServerOptions opts;
  opts.threads = num_threads;
  opts.shutdownOn = {SIGINT};
  opts.idleTimeout = std::chrono::milliseconds(15000);
  opts.enableContentCompression = false;
  opts.h2cEnabled = false;
  opts.listenBacklog = 65535;
  opts.maxConcurrentIncomingStreams = 1000;
  opts.initialReceiveWindow = 512 * 1024; // 512KB
  opts.receiveStreamWindowSize = 512 * 1024;
  opts.receiveSessionWindowSize = MAX_BUFFER_SIZE; // per session
  opts.useZeroCopy = true;
  opts.enableExHeaders = false;

  std::vector<proxygen::HTTPServer::IPConfig> ip_configs = {
    {folly::SocketAddress("0.0.0.0", 8443), proxygen::HTTPServer::Protocol::HTTP, nullptr}};
  ip_configs[0].enableTCPFastOpen = true;
  ip_configs[0].acceptorSocketOptions = std::move(create_socket_opt());

  auto cwd = std::filesystem::current_path();
  // Configure H server
  s_h_server h(std::move(opts));
  h.set_domains({"localhost"}).set_alpn_protocols({"http/1.1"}).set_ips(std::move(ip_configs));

  auto server = s_proxygen_server::make()->set_num_threads(num_threads)->set_h(std::move(h));

  std::thread server_thread([server] {
    server->run_forever(
      []([[maybe_unused]] proxygen::HTTPMessage* p_req) -> proxygen::HTTPTransactionHandler* {
        return new hello_handler();
      });
  });

  // Wait for server to start and then stop it
  std::this_thread::sleep_for(sleep_duration);
  server->stop();
  server_thread.join();
}

BENCHMARK(s_h2_proxygen_server_start_stop) {
  const auto num_threads = std::thread::hardware_concurrency();

  proxygen::HTTPServerOptions opts;
  opts.threads = num_threads;
  opts.shutdownOn = {SIGINT};
  opts.idleTimeout = std::chrono::milliseconds(15000);
  opts.enableContentCompression = false;
  opts.h2cEnabled = false;
  opts.listenBacklog = 65535;
  opts.maxConcurrentIncomingStreams = 1000;
  opts.initialReceiveWindow = 512 * 1024; // 512KB
  opts.receiveStreamWindowSize = 512 * 1024;
  opts.receiveSessionWindowSize = MAX_BUFFER_SIZE; // per session
  opts.useZeroCopy = true;
  opts.enableExHeaders = false;

  std::vector<proxygen::HTTPServer::IPConfig> ip_configs = {
    {folly::SocketAddress("0.0.0.0", 8443), proxygen::HTTPServer::Protocol::HTTP2, nullptr}};
  ip_configs[0].enableTCPFastOpen = true;
  ip_configs[0].acceptorSocketOptions = std::move(create_socket_opt());

  auto cwd = std::filesystem::current_path();
  // Configure H2 server
  s_h_server h(std::move(opts));
  h.set_domains({"localhost"})
    .set_chain(cwd / "../dep/proxygen/proxygen/httpserver/tests/certs/ca_cert.pem")
    .set_cert(cwd / "../dep/proxygen/proxygen/httpserver/tests/certs/ca_cert.pem")
    .set_key(cwd / "../dep/proxygen/proxygen/httpserver/tests/certs/ca_key.pem")
    .set_ips(std::move(ip_configs));

  auto server = s_proxygen_server::make()->set_num_threads(num_threads)->set_h(std::move(h));

  std::thread server_thread([server] {
    server->run_forever(
      []([[maybe_unused]] proxygen::HTTPMessage* p_req) -> proxygen::HTTPTransactionHandler* {
        return new hello_handler();
      });
  });

  // Wait for server to start and then stop it
  std::this_thread::sleep_for(sleep_duration);
  server->stop();
  server_thread.join();
}

BENCHMARK(s_h2_tls_proxygen_server_start_stop) {
  const auto num_threads = std::thread::hardware_concurrency();

  proxygen::HTTPServerOptions opts;
  opts.threads = num_threads;
  opts.shutdownOn = {SIGINT};
  opts.idleTimeout = std::chrono::milliseconds(15000);
  opts.enableContentCompression = false;
  opts.h2cEnabled = false;
  opts.listenBacklog = 65535;
  opts.maxConcurrentIncomingStreams = 1000;
  opts.initialReceiveWindow = 512 * 1024; // 512KB
  opts.receiveStreamWindowSize = 512 * 1024;
  opts.receiveSessionWindowSize = MAX_BUFFER_SIZE; // per session
  opts.useZeroCopy = true;
  opts.enableExHeaders = false;

  std::vector<proxygen::HTTPServer::IPConfig> ip_configs = {
    {folly::SocketAddress("0.0.0.0", 8443), proxygen::HTTPServer::Protocol::HTTP2, nullptr}};
  ip_configs[0].enableTCPFastOpen = true;
  ip_configs[0].acceptorSocketOptions = std::move(create_socket_opt());

  auto cwd = std::filesystem::current_path();
  // Configure H2 server
  s_h_server h(std::move(opts));
  h.set_domains({"localhost"})
    .set_chain(cwd / "../dep/proxygen/proxygen/httpserver/tests/certs/ca_cert.pem")
    .set_cert(cwd / "../dep/proxygen/proxygen/httpserver/tests/certs/ca_cert.pem")
    .set_key(cwd / "../dep/proxygen/proxygen/httpserver/tests/certs/ca_key.pem")
    .set_alpn_protocols({"h2", "http/1.1"})
    .set_ips(std::move(ip_configs));

  auto server = s_proxygen_server::make()->set_num_threads(num_threads)->set_h(std::move(h));

  std::thread server_thread([server] {
    server->run_forever(
      []([[maybe_unused]] proxygen::HTTPMessage* p_req) -> proxygen::HTTPTransactionHandler* {
        return new hello_handler();
      });
  });

  // Wait for server to start and then stop it
  std::this_thread::sleep_for(sleep_duration);
  server->stop();
  server_thread.join();
}

#endif // SIB_NET_PROXYGEN