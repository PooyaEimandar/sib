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

// #ifdef SIB_NET_GATEKEEPER

#pragma once

#include <folly/TokenBucket.h>
#include <folly/io/async/AsyncServerSocket.h>
#include <folly/io/async/AsyncSocket.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/EventBaseManager.h>
#include <folly/logging/xlog.h>
#include <folly/net/NetOps.h>

#include <memory>
#include <mutex>
#include <unordered_map>

#include "s_rate_limiter.hpp"

namespace sib::network {

constexpr size_t BUFFER_SIZE = 8192;

struct s_duplex_bridge : public std::enable_shared_from_this<s_duplex_bridge> {
  // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
  s_duplex_bridge(folly::AsyncSocket::UniquePtr&& p_lhs, folly::AsyncSocket::UniquePtr&& p_rhs)
    : lhs_(std::move(p_lhs)), rhs_(std::move(p_rhs)) {}

  ~s_duplex_bridge() {
    if (lhs_) {
      lhs_->closeNow();
      lhs_->setReadCB(nullptr);
    }
    if (rhs_) {
      rhs_->closeNow();
      rhs_->setReadCB(nullptr);
    }
  }

  s_duplex_bridge(const s_duplex_bridge&) = delete;
  auto operator=(const s_duplex_bridge&) -> s_duplex_bridge& = delete;
  s_duplex_bridge(s_duplex_bridge&&) = default;
  auto operator=(s_duplex_bridge&&) -> s_duplex_bridge& = default;

  void start() {
    if (lhs_cb_) {
      lhs_cb_->shutdown();
      lhs_cb_.reset();
    }
    if (rhs_cb_) {
      rhs_cb_->shutdown();
      rhs_cb_.reset();
    }

    lhs_cb_ = std::make_unique<s_pipe_read_cb>(lhs_.get(), shared_from_this(), rhs_.get());
    rhs_cb_ = std::make_unique<s_pipe_read_cb>(rhs_.get(), shared_from_this(), lhs_.get());

    lhs_->setReadCB(lhs_cb_.get());
    rhs_->setReadCB(rhs_cb_.get());
  }

  struct s_pipe_read_cb : public folly::AsyncTransport::ReadCallback {
    s_pipe_read_cb(
      folly::AsyncSocket* p_from,
      std::shared_ptr<s_duplex_bridge> p_bridge,
      folly::AsyncSocket* p_to)
      : parent_(std::move(p_bridge)), from_(p_from), to_(p_to) {}

    void getReadBuffer(void** p_buf_return, size_t* p_len_return) override {
      *p_buf_return = buffer_.data();
      *p_len_return = buffer_.size();
    }

    void readDataAvailable(size_t p_len) noexcept override {
      if (to_ && to_->good() && p_len > 0) {
        to_->write(nullptr, buffer_.data(), p_len);
      }
    }

    void readEOF() noexcept override { shutdown(); }
    void readErr([[maybe_unused]] const folly::AsyncSocketException& p_exc) noexcept override {
      shutdown();
    }

    void shutdown() {
      from_->closeNow();
      to_->closeNow();
    }

   private:
    std::array<char, BUFFER_SIZE> buffer_ = {'\0'};
    std::shared_ptr<s_duplex_bridge> parent_;
    folly::AsyncSocket* from_;
    folly::AsyncSocket* to_;
  };

 private:
  std::unique_ptr<s_pipe_read_cb> lhs_cb_;
  std::unique_ptr<s_pipe_read_cb> rhs_cb_;
  folly::AsyncSocket::UniquePtr lhs_;
  folly::AsyncSocket::UniquePtr rhs_;
};

template <typename Duration>
struct s_tcp_gate_keeper : public folly::AsyncServerSocket::AcceptCallback {
  s_tcp_gate_keeper(
    uint16_t p_listen_port,
    folly::SocketAddress&& p_forward_addr,
    int p_backlog,
    Duration p_timeout,
    std::shared_ptr<s_rate_limiter<Duration>> p_rate_limiter)
    : listen_port_(p_listen_port), forward_addr_(std::move(p_forward_addr)), backlog_(p_backlog),
      timeout_(p_timeout), rate_limiter_(std::move(p_rate_limiter)) {}

  void start() {
    server_socket_ = folly::AsyncServerSocket::newSocket(&evb_);
    server_socket_->bind(listen_port_);
    server_socket_->listen(backlog_);
    server_socket_->addAcceptCallback(this, &evb_);
    server_socket_->startAccepting();

    XLOG(INFO) << "Gatekeeper started on port: " << listen_port_;
    evb_.loop();
  }

  void connectionAccepted(
    folly::NetworkSocket p_fd,
    const folly::SocketAddress& p_client_addr,
    [[maybe_unused]] AcceptInfo p_info) noexcept override {
    try {
      const auto& ip_addr = p_client_addr.getAddressStr();

      if (rate_limiter_ && rate_limiter_->is_limited(ip_addr)) {
        XLOG(WARNING) << "Rate limited connection from " << ip_addr << " to "
                      << forward_addr_.getAddressStr() << ":" << forward_addr_.getPort();
        ::close(p_fd.toFd());
        return;
      }

      auto client_sock = folly::AsyncSocket::UniquePtr(new folly::AsyncSocket(&evb_, p_fd));

      auto upstream_sock = folly::AsyncSocket::newSocket(&evb_);
      upstream_sock->connect(
        nullptr, forward_addr_, std::chrono::duration_cast<std::chrono::milliseconds>(timeout_));

      auto bridge =
        std::make_shared<s_duplex_bridge>(std::move(client_sock), std::move(upstream_sock));
      bridge->start();

    } catch (const std::exception& p_exc) {
      XLOG(ERR) << "connectionAccepted got an error: " << p_exc.what();
    }
  }

  void acceptError(const std::exception& p_exc) noexcept override {
    XLOG(ERR) << "Accept error in gatekeeper: " << p_exc.what();
  }

 private:
  folly::EventBase evb_;
  std::shared_ptr<folly::AsyncServerSocket> server_socket_;
  folly::SocketAddress forward_addr_;
  uint16_t listen_port_;
  Duration timeout_;
  int backlog_;
  std::shared_ptr<s_rate_limiter<Duration>> rate_limiter_;
};

} // namespace sib::network

// #endif // SIB_NET_GATEKEEPER
