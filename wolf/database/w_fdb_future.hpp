// #ifdef WOLF_DB_FDB

#pragma once

#include <folly/coro/Coroutine.h>
#include <folly/coro/Sleep.h>
#include <folly/coro/Task.h>
#include <folly/coro/Timeout.h>
#include <wolf/database/w_fdb.hpp>

namespace wolf::db {

struct w_fdb_future {
 public:
  explicit w_fdb_future(FDBFuture* p_future) noexcept : future_(p_future) {}

  [[nodiscard]] auto await_ready() const noexcept -> bool { return fdb_future_is_ready(future_); }

  auto await_suspend(folly::coro::coroutine_handle<> p_handle) noexcept -> void {
    handle_ = p_handle;

    const fdb_error_t FDB_ERR = fdb_future_set_callback(
      future_,
      []([[maybe_unused]] FDBFuture* p_fut, void* p_ctx) {
        auto* self = static_cast<w_fdb_future*>(p_ctx);
        self->handle_.resume();
      },
      static_cast<void*>(this));

    if (FDB_ERR != 0) {
      p_handle.resume(); // resume immediately on failure
    }
  }

  void await_resume() const noexcept {
    // No-op: result handled outside
  }

 private:
  FDBFuture* future_;
  mutable folly::coro::coroutine_handle<> handle_;
};

constexpr auto INTERVAL_POOL = std::chrono::milliseconds(5);
template <typename Duration>
inline auto w_fdb_wait_for_fut(
  Duration p_timeout, FDBFuture* p_fut, Duration p_interval_pool = INTERVAL_POOL)
  -> folly::coro::Task<bool> {
  if (!p_fut) {
    co_return false;
  }

  const auto DEADLINE = std::chrono::steady_clock::now() + p_timeout;
  while (std::chrono::steady_clock::now() < DEADLINE) {
    if (fdb_future_is_ready(p_fut)) {
      co_return fdb_future_get_error(p_fut) == 0;
    }
    co_await folly::coro::sleep(p_interval_pool);
  }

  // timeout reached
  co_return false;
}

} // namespace wolf::db

// #endif // WOLF_DB_FDB
