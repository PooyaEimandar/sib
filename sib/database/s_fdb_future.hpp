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

#ifdef SIB_DB_FDB

#pragma once

#include <folly/coro/Coroutine.h>
#include <folly/coro/Sleep.h>
#include <folly/coro/Task.h>
#include <folly/coro/Timeout.h>
#include <folly/futures/ThreadWheelTimekeeper.h>

#include <sib/database/s_fdb.hpp>

namespace sib::db {

struct s_fdb_future {
 public:
  explicit s_fdb_future(FDBFuture* p_future) noexcept : future_(p_future) {}

  [[nodiscard]] auto await_ready() const noexcept -> bool { return fdb_future_is_ready(future_); }

  auto await_suspend(folly::coro::coroutine_handle<> p_handle) noexcept -> void {
    handle_ = p_handle;

    const fdb_error_t FDB_ERR = fdb_future_set_callback(
      future_,
      []([[maybe_unused]] FDBFuture* p_fut, void* p_ctx) {
        auto* self = static_cast<s_fdb_future*>(p_ctx);
        self->handle_.resume();
      },
      static_cast<void*>(this));

    if (FDB_ERR != 0) {
      // resume immediately on failure
      p_handle.resume();
    }
  }

  void await_resume() const noexcept {
    // No-op: result handled outside
  }

 private:
  FDBFuture* future_ = nullptr;
  mutable folly::coro::coroutine_handle<> handle_ = nullptr;
};

constexpr auto INTERVAL_POOL = std::chrono::milliseconds(5);
template <typename Duration>
inline auto s_fdb_wait_for_fut(
  Duration p_timeout,
  FDBFuture* p_fut,
  folly::Timekeeper* p_tk,
  Duration p_interval_pool = INTERVAL_POOL) -> folly::coro::Task<bool> {
  if (!p_fut) {
    co_return false;
  }

  const auto DEADLINE = std::chrono::steady_clock::now() + p_timeout;
  while (std::chrono::steady_clock::now() < DEADLINE) {
    if (fdb_future_is_ready(p_fut)) {
      co_return fdb_future_get_error(p_fut) == 0;
    }
    co_await folly::coro::sleep(p_interval_pool, p_tk);
  }

  // timeout reached
  co_return false;
}

} // namespace sib::db

#endif // SIB_DB_FDB
