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

#include <sib/sib.hpp>

#include <filesystem>
#include <memory>
#include <string_view>

#include <folly/executors/CPUThreadPoolExecutor.h>
#include <folly/logging/xlog.h>
#include <proxygen/httpserver/HTTPServer.h>
#include <proxygen/httpserver/HTTPServerAcceptor.h>
#include <proxygen/httpserver/HTTPTransactionHandlerAdaptor.h>
#include <proxygen/httpserver/RequestHandlerFactory.h>
#include <proxygen/httpserver/samples/hq/HQCommandLine.h>
#include <proxygen/httpserver/samples/hq/HQServer.h>
#include <sib/network/s_rate_limiter.hpp>

namespace sib::network::http {

using handler_fn = quic::samples::HTTPTransactionHandlerProvider;

// Forward declaration
struct s_proxygen_server;

struct handler_factory : public proxygen::RequestHandlerFactory {
  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  explicit handler_factory(handler_fn&& p_handler) : handler_(std::move(p_handler)) {}

  void onServerStart([[maybe_unused]] folly::EventBase* p_evb) noexcept override {}

  void onServerStop() noexcept override {}

  auto onRequest(
    [[maybe_unused]] proxygen::RequestHandler* p_handler,
    proxygen::HTTPMessage* p_http_req) noexcept -> proxygen::RequestHandler* override {
    try {
      // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
      return new proxygen::HTTPTransactionHandlerAdaptor(handler_(p_http_req));
    } catch (const std::exception& p_exc) {
      XLOG(ERR) << "Failed to create HTTPTransactionHandlerAdaptor because:" << p_exc.what();
      return nullptr;
    }
  }

 private:
  handler_fn handler_;
};

struct s_h2_server {
  // NOLINTBEGIN(cppcoreguidelines-rvalue-reference-param-not-moved,
  // cppcoreguidelines-pro-type-member-init,hicpp-member-init)
  explicit s_h2_server(proxygen::HTTPServerOptions&& p_param) : param_(std::move(p_param)) {}
  // NOLINTEND

  ~s_h2_server() = default;

  s_h2_server(s_h2_server&&) noexcept = default;
  auto operator=(s_h2_server&&) noexcept -> s_h2_server& = default;
  s_h2_server(const s_h2_server&) = delete;
  auto operator=(s_h2_server&) -> s_h2_server& = delete;

  auto set_chain(const std::filesystem::path& p_chain) -> s_h2_server& {
    chain_path_ = p_chain;
    return *this;
  }

  auto set_cert(const std::filesystem::path& p_cert) -> s_h2_server& {
    cert_path_ = p_cert;
    return *this;
  }

  auto set_key(const std::filesystem::path& p_key) -> s_h2_server& {
    key_path_ = p_key;
    return *this;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  auto set_domains(std::vector<std::string>&& p_domains) -> s_h2_server& {
    domains_ = std::move(p_domains);
    return *this;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  auto set_ips(std::vector<proxygen::HTTPServer::IPConfig>&& p_ip_configs) -> s_h2_server& {
    ip_configs_ = std::move(p_ip_configs);
    return *this;
  }

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  auto set_alpn_protocols(std::list<std::string>&& p_alpn_protocols) -> s_h2_server& {
    alpn_protocols_ = std::move(p_alpn_protocols);
    return *this;
  }

 private:
  friend struct s_proxygen_server;

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  auto start(handler_fn&& p_handler) -> s_result<int> {
    if (server_) {
      return S_ERROR(std::errc::already_connected, "h2 server is already started");
    }

    // enable TLS
    if (
      std::filesystem::exists(chain_path_) && std::filesystem::exists(cert_path_) &&
      std::filesystem::exists(key_path_)) {
      // initialize ssl config
      wangle::SSLContextConfig ssl_config;
      ssl_config.isDefault = true;
      ssl_config.domains = std::move(domains_);
      ssl_config.clientVerification = folly::SSLContext::VerifyClientCertificate::IF_PRESENTED;
      ssl_config.setNextProtocols(alpn_protocols_);
      ssl_config.clientCAFile = cert_path_;
      ssl_config.setCertificate(chain_path_, key_path_, "");

      for (auto& ipc : ip_configs_) {
        ipc.sslConfigs.emplace_back(ssl_config);
      }
    }

    try {
      // setup handler factory
      param_.handlerFactories =
        proxygen::RequestHandlerChain().addThen<handler_factory>(std::move(p_handler)).build();
      server_ = std::make_unique<proxygen::HTTPServer>(std::move(param_));

      server_->bind(ip_configs_);
      server_->start();

      return S_SUCCESS;
    } catch (const std::exception& p_exc) {
      server_.reset();
      return S_ERROR(
        std::errc::operation_canceled,
        folly::sformat("failed to start h2 server: {}", p_exc.what()));
    }
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  auto stop() -> s_result<int> {
    if (server_) {
      server_->stop();
      server_.reset();
    }
    return S_SUCCESS;
  }

  std::filesystem::path chain_path_;
  std::filesystem::path cert_path_;
  std::filesystem::path key_path_;
  std::vector<std::string> domains_ = {"localhost"};
  std::list<std::string> alpn_protocols_ = {"h2", "http/1.1"};
  std::vector<proxygen::HTTPServer::IPConfig> ip_configs_ = {
    {folly::SocketAddress("::1", 8443), proxygen::HTTPServer::Protocol::HTTP2, nullptr}};
  proxygen::HTTPServerOptions param_;
  std::unique_ptr<proxygen::HTTPServer> server_;
};

struct s_h3_server {
  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved,cppcoreguidelines-pro-type-member-init,hicpp-member-init)
  explicit s_h3_server(quic::samples::HQToolServerParams&& p_param) : param_(std::move(p_param)) {}
  ~s_h3_server() = default;

  s_h3_server(s_h3_server&&) noexcept = default;
  auto operator=(s_h3_server&&) noexcept -> s_h3_server& = default;
  s_h3_server(const s_h3_server&) = delete;
  auto operator=(s_h3_server&) -> s_h3_server& = delete;

 private:
  friend struct s_proxygen_server;

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved,readability-convert-member-functions-to-static)
  auto start(handler_fn&& p_handler) -> s_result<int> {
    if (server_) {
      return S_ERROR(std::errc::already_connected, "h3 server is already started");
    }

    try {
      server_ = std::make_unique<quic::samples::HQServer>(param_, std::move(p_handler), nullptr);

      // start h3 server
      server_->start();
      // wait for getting the address of the server
      const auto& addr = server_->getAddress();
      XLOG(INFO) << "Sib H3 server started successfully on: " << addr.getAddressStr();
    } catch (const std::exception& p_exc) {
      server_.reset();
      return S_ERROR(
        std::errc::not_enough_memory,
        folly::sformat("failed to start h3 server: {}", p_exc.what()));
    }

    return S_SUCCESS;
  }

  // NOLINTNEXTLINE(readability-convert-member-functions-to-static)
  auto stop() {
    if (server_) {
      server_->rejectNewConnections(true);
      server_->stop();
      server_.reset();
    }
    if (baton_) {
      baton_->post();
      baton_.reset();
    }
  }

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  auto start_forever(handler_fn&& p_handler) -> s_result<int> {
    try {
      auto res = start(std::move(p_handler));
      if (!res) {
        return res;
      }
      baton_ = std::make_unique<folly::Baton<>>();
      baton_->wait();
    } catch (const std::exception& p_exc) {
      stop();
      server_.reset();
      return S_ERROR(
        std::errc::operation_canceled,
        folly::sformat("failed to start h3 start_forever: {}", p_exc.what()));
    }
    return S_SUCCESS;
  }

  std::unique_ptr<folly::Baton<>> baton_;
  quic::samples::HQToolServerParams param_{};
  std::unique_ptr<quic::samples::HQServer> server_;
};

struct s_proxygen_server : public std::enable_shared_from_this<s_proxygen_server> {
  s_proxygen_server(s_proxygen_server&&) = default;
  auto operator=(s_proxygen_server&&) -> s_proxygen_server& = default;
  s_proxygen_server(const s_proxygen_server&) = delete;
  auto operator=(s_proxygen_server&) -> s_proxygen_server& = delete;

  ~s_proxygen_server() {
    if (h2_) {
      h2_->stop();
    }
    if (h3_) {
      h3_->stop();
    }
  }

  static auto make() -> std::shared_ptr<s_proxygen_server> {
    return std::shared_ptr<s_proxygen_server>(new s_proxygen_server());
  }

  auto set_num_threads(uint32_t p_num) -> std::shared_ptr<s_proxygen_server> {
    num_threads_ = p_num;
    return shared_from_this();
  }

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  auto set_h2(s_h2_server&& p_h2) -> std::shared_ptr<s_proxygen_server> {
    if (h2_) {
      h2_->stop();
      h2_.reset();
    }
    h2_ = std::move(p_h2);
    return shared_from_this();
  }

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  auto set_h3(quic::samples::HQToolServerParams&& p_param) -> std::shared_ptr<s_proxygen_server> {
    if (h3_) {
      h3_->stop();
      h3_.reset();
    }
    h3_ = s_h3_server(std::move(p_param));
    return shared_from_this();
  }

  // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
  auto run_forever(sib::network::http::handler_fn&& p_handler) -> s_result<int> {
    if (!p_handler) {
      return S_ERROR(std::errc::operation_canceled, "missing handler for http server.");
    }
    if (!folly::getUnsafeMutableGlobalCPUExecutor()) {
      if (num_threads_ == 0) {
        num_threads_ = std::thread::hardware_concurrency();
      }
      auto pool = std::make_shared<folly::CPUThreadPoolExecutor>(
        num_threads_, std::make_shared<folly::NamedThreadFactory>("StaticDiskIOThread"));
      folly::setUnsafeMutableGlobalCPUExecutor(std::static_pointer_cast<folly::Executor>(pool));
    }

    // make sure the handler is shared
    if (h2_ && h3_) {
      auto shared_handler = std::make_shared<handler_fn>(std::move(p_handler));
      std::thread h2_thread([p_handler = shared_handler, this]() mutable {
        h2_->start(std::move(*p_handler));
      });

      auto result = h3_->start(std::move(*shared_handler));
      h2_thread.join();
      return result;
    }

    if (h2_) {
      return h2_->start(std::move(p_handler));
    }

    if (h3_) {
      return h3_->start_forever(std::move(p_handler));
    }

    return S_ERROR(std::errc::operation_canceled, "Neither H2 nor H3 enabled.");
  }

  void stop() {
    if (h2_) {
      h2_->stop();
    }
    if (h3_) {
      h3_->stop();
    }
  }

  [[nodiscard]] auto get_num_threads() const -> uint16_t { return num_threads_; }

  [[nodiscard]] auto get_h2() const -> const s_h2_server* { return h2_ ? &*h2_ : nullptr; }

  [[nodiscard]] auto get_h3() const -> const s_h3_server* { return h3_ ? &*h3_ : nullptr; }

 private:
  s_proxygen_server() = default;

  uint16_t num_threads_ = 0;
  std::optional<s_h2_server> h2_;
  std::optional<s_h3_server> h3_;
};

} // namespace sib::network::http

#endif // SIB_NET_PROXYGEN
