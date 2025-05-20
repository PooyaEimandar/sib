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

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>

#include <folly/container/F14Map.h>

template <typename Duration>
struct s_rate_limiter {
  enum class mode : std::uint8_t { SLIDING_WINDOW, FIXED_WINDOW };

  s_rate_limiter(size_t p_max_conn, Duration&& p_window, mode p_mode)
    : max_conn_(static_cast<double>(p_max_conn)), window_(std::move(p_window)), mode_(p_mode) {}

  ~s_rate_limiter() = default;

  s_rate_limiter(const s_rate_limiter&) = delete;
  auto operator=(const s_rate_limiter&) -> s_rate_limiter& = delete;
  s_rate_limiter(s_rate_limiter&&) = delete;
  auto operator=(s_rate_limiter&&) -> s_rate_limiter& = delete;

  auto is_limited(const std::string& p_ip) -> bool {
    const auto NOW = std::chrono::steady_clock::now();
    const std::lock_guard<std::mutex> LOCK(mutex_);

    auto& entry = map_[p_ip];

    if (entry.first.time_since_epoch().count() == 0) {
      entry = {NOW, 1.0};
      return false;
    }

    if (mode_ == mode::FIXED_WINDOW) {
      if (NOW - entry.first > window_) {
        entry = {NOW, 1.0};
        return false;
      }
      if (entry.second >= max_conn_) {
        return true;
      }
      ++entry.second;
      return false;
    }

    const auto ELAPSED = std::chrono::duration<double>(NOW - entry.first).count();
    const double REFILL = max_conn_ * (ELAPSED / window_.count());

    entry.second = std::min<double>(entry.second + REFILL, max_conn_);
    if (entry.second < 1.0) {
      return true;
    }
    entry.first = NOW;
    entry.second -= 1.0;
    return false;
  }

 private:
  double max_conn_;
  Duration window_;
  mode mode_;
  std::mutex mutex_;
  folly::F14FastMap<std::string, std::pair<std::chrono::steady_clock::time_point, double>> map_;
};

// #endif // SIB_NET_GATEKEEPER
