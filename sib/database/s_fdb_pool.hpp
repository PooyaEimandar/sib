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

#include "s_fdb_trans.hpp"

#include <filesystem>
#include <folly/coro/WithCancellation.h>
#include <folly/logging/xlog.h>
#include <folly/small_vector.h>

namespace sib::db {
constexpr auto FDB_MAX_POOL_SIZE = 16;
struct s_fdb_pool {
  static auto init(std::filesystem::path& p_path, size_t p_pool_size) -> s_result<int> {
    if (!std::filesystem::exists(p_path)) {
      return S_ERROR(std::errc::no_such_file_or_directory, "Missing cluster file");
    }
    s_cluster_file_path = p_path.string();

    run_network();

    auto state = pool().wlock();
    for (size_t i = 0; i < p_pool_size; ++i) {
      FDBDatabase* fdb = nullptr;
      auto fdb_err = fdb_create_database(s_cluster_file_path.c_str(), &fdb);
      if (fdb_err) {
        return S_ERROR(
          fdb_err, folly::sformat("fdb_create_database got an error: {} ", fdb_get_error(fdb_err)));
      }
      state->pool.push_back(fdb);
    }
    return S_SUCCESS;
  }

  template <typename Duration>
  static auto acquire(Duration p_timeout, folly::Timekeeper* p_timekeeper)
    -> folly::coro::Task<s_result<fdb>> {
    auto state = pool().wlock();

    if (state->pool.empty()) {
      co_return S_ERROR(std::errc::device_or_resource_busy, "FDB pool is empty");
    }

    const size_t POOL_SIZE = state->pool.size();
    const size_t START_INDEX = s_current_index.load();
    for (size_t i = 0; i < POOL_SIZE; ++i) {
      const size_t INDEX = (START_INDEX + i) % POOL_SIZE;
      if (!state->in_use.contains(INDEX)) {
        auto* conn = state->pool[INDEX];
        if (!conn) {
          continue;
        }

        auto available = co_await is_db_available(conn, p_timeout, p_timekeeper);
        if (!available) {
          continue;
        }

        state->in_use.insert(INDEX);
        state->connection_index[conn] = INDEX;
        s_current_index.store((INDEX + 1) % POOL_SIZE);

        co_return conn;
      }
    }

    co_return S_ERROR(std::errc::resource_unavailable_try_again, "No available FDB connections");
  }

  static void release(fdb p_conn) {
    auto state = pool().wlock();
    auto iter = state->connection_index.find(p_conn);
    if (iter != state->connection_index.end()) {
      state->in_use.erase(iter->second);
      state->connection_index.erase(iter);
    }
  }

  static auto fini() -> s_result<int> {
    auto state = pool().wlock();
    for (auto& iter : state->pool) {
      if (iter) {
        fdb_database_destroy(iter);
      }
    }
    state->pool.clear();
    state->in_use.clear();
    state->connection_index.clear();

    auto fdb_err = fdb_stop_network();
    if (s_network_thread.joinable()) {
      s_network_thread.join();
    }
    if (fdb_err) {
      return S_ERROR(
        fdb_err, folly::sformat("fdb_stop_network got an error: {} ", fdb_get_error(fdb_err)));
    }
    return S_SUCCESS;
  }

  template <typename Callback, typename Duration>
  static auto watch(
    fdb p_conn,
    Duration p_timeout,
    folly::fbstring p_key,
    Callback p_on_change,
    folly::CancellationToken p_cancel_token) -> folly::coro::Task<s_result<int>> {
    while (!p_cancel_token.isCancellationRequested()) {
      // create a transaction
      FDBTransaction* trans = nullptr;
      const auto TRANS_ERR = fdb_database_create_transaction(p_conn, &trans);
      if (TRANS_ERR) {
        co_return S_ERROR(
          TRANS_ERR, folly::sformat("Failed to create transaction: {}", fdb_get_error(TRANS_ERR)));
      }

      // NOLINTBEGIN (cppcoreguidelines-pro-type-reinterpret-cast)
      auto* fut =
        fdb_transaction_watch(trans, reinterpret_cast<const uint8_t*>(p_key.data()), p_key.size());
      // NOLINTEND
      if (!fut) {
        fdb_transaction_destroy(trans);
        co_return S_ERROR(std::errc::operation_canceled, "Failed to create watch future");
      }

      S_DEFER([trans, fut]() noexcept {
        fdb_future_destroy(fut);
        fdb_transaction_destroy(trans);
      });

      try {
        co_await folly::coro::co_withCancellation(p_cancel_token, [&]() -> folly::coro::Task<void> {
          co_await s_fdb_future(fut);
          co_return;
        }());
      } catch (const folly::OperationCancelled& p_excp) {
        co_return S_ERROR(
          std::errc::operation_canceled, folly::sformat("Watch loop cancelled for key: {}", p_key));
      }

      // Try to get the new value using s_fdb_trans
      auto trans_result = s_fdb_trans::make(p_conn);
      if (!trans_result) {
        co_return S_ERROR(
          std::errc::io_error,
          folly::sformat("Failed to create transaction for get new key value of watch: {}", p_key));
      }

      auto new_value_result = co_await trans_result->get(p_timeout, p_key, false);
      // invoke the callback with the new value result
      std::invoke(std::forward<Callback>(p_on_change), std::move(new_value_result));
    }

    co_return S_SUCCESS;
  }

  static auto size() -> size_t { return pool().rlock()->pool.size(); }
  static auto in_use() -> size_t { return pool().rlock()->in_use.size(); }
  static auto available() -> size_t {
    const auto& state = pool().rlock();
    return state->pool.size() > state->in_use.size()
      ? state->pool.size() - state->in_use.size()
      : 0;
  }

 private:
  struct pool_t {
    folly::small_vector<fdb, FDB_MAX_POOL_SIZE> pool;
    folly::F14FastSet<size_t> in_use;
    folly::F14FastMap<fdb, size_t> connection_index;
  };

  static auto pool() -> folly::Synchronized<pool_t>& {
    static folly::Synchronized<pool_t> instance;
    return instance;
  }

  template <typename Duration>
  static auto is_db_available(fdb p_conn, Duration p_timeout, folly::Timekeeper* p_tk)
    -> folly::coro::Task<bool> {
    FDBTransaction* trans = nullptr;
    auto fdb_err = fdb_database_create_transaction(p_conn, &trans);
    if (fdb_err != 0) {
      co_return false;
    }

    auto* fut = fdb_transaction_get_read_version(trans);
    if (!fut) {
      fdb_transaction_destroy(trans);
      co_return false;
    }

    S_DEFER([fut, trans]() noexcept {
      fdb_future_destroy(fut);
      fdb_transaction_destroy(trans);
    });

    co_return co_await s_fdb_wait_for_fut(p_timeout, fut, p_tk);
  }

  static void run_network() {
    static std::once_flag once;
    std::call_once(once, [&] {
      auto fdb_err = fdb_select_api_version(FDB_API_VERSION);
      if (fdb_err) {
        // NOLINTNEXTLINE
        XLOG(ERR) << "fdb_select_api_version got an error: " << fdb_get_error(fdb_err);
        return;
      }
      fdb_err = fdb_setup_network();
      if (fdb_err) {
        // NOLINTNEXTLINE
        XLOG(ERR) << "fdb_setup_network got an error: " << fdb_get_error(fdb_err);
        return;
      }

      s_network_thread = std::thread([] {
        s_network_started.store(true, std::memory_order_release);
        const auto& fdb_err = fdb_run_network();
        if (fdb_err) {
          // NOLINTNEXTLINE
          XLOG(ERR) << "fdb_run_network got an error: " << fdb_get_error(fdb_err);
        }
      });
    });

    while (!s_network_started.load(std::memory_order_acquire)) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
  }

  static inline folly::fbstring s_cluster_file_path;
  static inline std::atomic<size_t> s_current_index = 0;
  static inline std::thread s_network_thread;
  static inline std::atomic<bool> s_network_started = false;
};
} // namespace sib::db

#endif // SIB_DB_FDB