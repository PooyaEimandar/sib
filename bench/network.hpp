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

#pragma once

#include <folly/Benchmark.h>

#include <proxygen/lib/http/HTTPMessage.h>
#include <proxygen/lib/http/session/HTTPTransaction.h>

#include <sib/network/s_proxygen_server.hpp>

using namespace sib::network::http;

struct hello_handler : public proxygen::HTTPTransaction::Handler {
  virtual void onHeadersComplete(
    std::unique_ptr<proxygen::HTTPMessage> p_headers) noexcept override {
    if (p_headers->getMethod() == proxygen::HTTPMethod::GET) {
      constexpr auto* body = "Hello from Sib!";
      constexpr auto* len = "15";

      proxygen::HTTPMessage response;
      response.setStatusCode(200);
      response.setStatusMessage("OK");
      response.setIsChunked(false);
      response.setWantsKeepalive(false);
      response.setHTTPVersion(1, 1);

      auto& headers = response.getHeaders();
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_TYPE, "text/plain");
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONTENT_LENGTH, len);
      headers.add(proxygen::HTTPHeaderCode::HTTP_HEADER_CONNECTION, "close");

      _txn->sendHeaders(response);

      _txn->sendBody(std::move(folly::IOBuf::copyBuffer(body, strlen(body))));
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

BENCHMARK(s_proxygen_server_start_stop) {
  proxygen::HTTPServerOptions opts;
  opts.threads = 1;
  opts.shutdownOn = {SIGINT};
  opts.idleTimeout = std::chrono::milliseconds(5000);
  opts.enableContentCompression = false;
  opts.h2cEnabled = false;
  opts.listenBacklog = 65535;
  opts.maxConcurrentIncomingStreams = 1000;
  opts.initialReceiveWindow = 512 * 1024; // 512KB
  opts.receiveStreamWindowSize = 512 * 1024;
  opts.receiveSessionWindowSize = 4 * 1024 * 1024; // 4MB per session
  opts.useZeroCopy = true;
  opts.enableExHeaders = false;

  std::vector<proxygen::HTTPServer::IPConfig> ip_configs = {
    {folly::SocketAddress("0.0.0.0", 8443), proxygen::HTTPServer::Protocol::HTTP2, nullptr}};

  auto cwd = std::filesystem::current_path();
  // Configure H2 server
  s_h2_server h2(std::move(opts));
  h2.set_domains({"localhost"})
    .set_chain(cwd / "../dep/proxygen/proxygen/httpserver/tests/certs/ca_cert.pem")
    .set_cert(cwd / "../dep/proxygen/proxygen/httpserver/tests/certs/ca_cert.pem")
    .set_key(cwd / "../dep/proxygen/proxygen/httpserver/tests/certs/ca_key.pem")
    .set_ips(std::move(ip_configs));

  auto server = s_proxygen_server::make()->set_num_threads(1)->set_h2(std::move(h2));

  std::thread server_thread([server] {
    server->run_forever(
      []([[maybe_unused]] proxygen::HTTPMessage* p_req) -> proxygen::HTTPTransactionHandler* {
        return new hello_handler();
      });
  });

  // Wait for server to start and then stop it after 5 seconds
  constexpr auto sleep_duration = std::chrono::seconds(5);
  std::this_thread::sleep_for(sleep_duration);
  server->stop();
  server_thread.join();
}
