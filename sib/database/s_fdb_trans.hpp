/*
 * Copyright (c) 2025 Pooya Eimandar (https://github.com/PooyaEimandar/sib)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef SIB_DB_FDB

#pragma once

#include <folly/FBString.h>
#include <folly/Format.h>

#include <sib/system/s_defer.hpp>
#include <sib/system/s_htobe64.hpp>
#include <sib/system/s_trace.hpp>

#include <sib/database/s_fdb_future.hpp>

namespace sib::db {

using fdb = FDBDatabase*;

struct s_fdb_range_view {
  std::shared_ptr<FDBFuture> fut_guard;
  folly::Range<const FDBKeyValue*> range;
  bool has_more = false;
};

// NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast,
// cppcoreguidelines-pro-type-cstyle-cast)
struct s_fdb_trans {
  static auto make(fdb p_db) -> boost::leaf::result<s_fdb_trans> {
    if (p_db == nullptr) {
      return S_ERROR(std::errc::not_supported, "Database connection is null");
    }
    FDBTransaction* trans = nullptr;
    const auto FDB_RES = fdb_database_create_transaction(p_db, &trans);
    if (FDB_RES) {
      return S_ERROR(FDB_RES, folly::sformat("FoundationDB error: {}", fdb_get_error(FDB_RES)));
    }
    return s_fdb_trans(trans);
  }

  s_fdb_trans(const s_fdb_trans&) = delete;
  auto operator=(const s_fdb_trans&) -> s_fdb_trans& = delete;
  s_fdb_trans(s_fdb_trans&& p_obj) noexcept { move_fn(p_obj); }
  auto operator=(s_fdb_trans&& p_obj) noexcept -> s_fdb_trans& {
    if (this != &p_obj) {
      move_fn(p_obj);
    }
    return *this;
  }
  ~s_fdb_trans() {
    if (trans_) {
      fdb_transaction_destroy(trans_);
    }
  }

  template <typename Duration>
  auto get(Duration p_timeout, std::string_view p_key, bool p_snapshot = false)
    -> folly::coro::Task<boost::leaf::result<folly::fbstring>> {
    auto* fut = fdb_transaction_get(
      trans_, reinterpret_cast<const uint8_t*>(p_key.data()), p_key.size(), p_snapshot);
    if (!fut) {
      co_return S_ERROR(std::errc::operation_canceled, "failed to create fdb future");
    }
    S_DEFER([fut]() noexcept {
      if (fut) {
        fdb_future_destroy(fut);
      }
    });

    auto res = co_await s_fdb_wait_for_fut(p_timeout, fut);
    if (!res) {
      co_return S_ERROR(
        std::errc::operation_canceled,
        fmt::format(
          "FoundationDB got timeout or error while waiting for future of key: {}", p_key));
    }

    fdb_bool_t present = 0;
    const uint8_t* val = nullptr;
    int len = 0;
    auto fdb_err = fdb_future_get_value(fut, &present, &val, &len);
    if (fdb_err) {
      co_return S_ERROR(
        fdb_err,
        folly::sformat(
          "FoundationDB got an error while reading key: {}. Error: {}",
          fdb_get_error(fdb_err),
          p_key));
    }
    if (!present) {
      co_return S_ERROR(std::errc::invalid_seek, "key not found");
    }
    co_return folly::fbstring((const char*)val, len);
  }

  template <typename Duration>
  auto read_range(
    Duration p_timeout,
    std::string_view p_begin,
    std::string_view p_end,
    bool p_begin_or_equal = false,
    int p_begin_offset = 0,
    bool p_end_or_equal = false,
    int p_end_offset = 1,
    int p_limit = 0,
    int p_target_bytes = 0,
    FDBStreamingMode p_mode = FDBStreamingMode::FDB_STREAMING_MODE_WANT_ALL,
    int p_iteration = 0,
    bool p_snapshot = false,
    bool p_reverse = false) -> folly::coro::Task<boost::leaf::result<s_fdb_range_view>> {
    // check if the range is valid
    if ((p_begin.empty() && p_end.empty()) || p_begin >= p_end) {
      co_return S_ERROR(
        std::errc::invalid_argument,
        "Invalid range: 'begin' key must be strictly less than 'end' key");
    }

    auto* fut_raw = fdb_transaction_get_range(
      trans_,
      (const uint8_t*)p_begin.data(),
      static_cast<int>(p_begin.size()),
      p_begin_or_equal,
      p_begin_offset,
      (const uint8_t*)p_end.data(),
      static_cast<int>(p_end.size()),
      p_end_or_equal,
      p_end_offset,
      p_limit,
      p_target_bytes,
      p_mode,
      p_iteration,
      p_snapshot,
      p_reverse);
    if (!fut_raw) {
      co_return S_ERROR(std::errc::operation_canceled, "fdb_transaction_get_range failed");
    }

    auto fut = std::shared_ptr<FDBFuture>(fut_raw, fdb_future_destroy);

    auto res = co_await s_fdb_wait_for_fut(p_timeout, fut);
    if (!res) {
      co_return S_ERROR(
        std::errc::operation_canceled,
        "FoundationDB got timeout or error while waiting for future of read_range");
    }

    const FDBKeyValue* kvs = nullptr;
    int count = 0;
    fdb_bool_t has_more = 0;
    auto fdb_err = fdb_future_get_keyvalue_array(fut_raw, &kvs, &count, &has_more);
    if (fdb_err) {
      co_return S_ERROR(
        fdb_err,
        fmt::format(
          "FoundationDB got an error while waiting for future. Error: {} ",
          fdb_get_error(fdb_err)));
    }

    co_return s_fdb_range_view{
      .fut_guard = fut,
      .range = folly::Range<const FDBKeyValue*>(kvs, kvs + count),
      .has_more = (has_more != 0),
    };
  }

  template <typename Duration>
  auto clear(std::string_view p_begin, std::optional<std::string_view> p_end)
    -> folly::coro::Task<boost::leaf::result<int>> {
    p_end
      ? fdb_transaction_clear_range(
          trans_,
          (const uint8_t*)p_begin.data(),
          p_begin.size(),
          (const uint8_t*)p_end->data(),
          p_end->size())
      : fdb_transaction_clear(trans_, (const uint8_t*)p_begin.data(), p_begin.size());
    co_return S_SUCCESS;
  }

  auto atomic_add_async(std::string_view p_key, int64_t p_value)
    -> folly::coro::Task<boost::leaf::result<int>> {
    auto value = sib::system::htobe64(p_value);

    fdb_transaction_atomic_op(
      trans_,
      reinterpret_cast<const uint8_t*>(p_key.data()),
      p_key.size(),
      (const uint8_t*)&value,
      sizeof(int64_t),
      FDB_MUTATION_TYPE_ADD);
    co_return S_SUCCESS;
  }

  template <typename Duration>
  auto commit(Duration p_timeout) -> folly::coro::Task<boost::leaf::result<int>> {
    auto* fut = fdb_transaction_commit(trans_);
    if (!fut) {
      co_return S_ERROR(std::errc::operation_canceled, "fdb_transaction_commit failed");
    }
    S_DEFER([fut]() noexcept {
      if (fut) {
        fdb_future_destroy(fut);
      }
    });

    auto res = co_await s_fdb_wait_for_fut(p_timeout, fut);
    if (!res) {
      co_return S_ERROR(
        std::errc::operation_canceled,
        "FoundationDB got timeout or error while waiting for future of commit");
    }

    co_return S_SUCCESS;
  }

  void set(std::string_view p_key, std::string_view p_val) {
    fdb_transaction_set(
      trans_,
      reinterpret_cast<const uint8_t*>(p_key.data()),
      p_key.size(),
      (const uint8_t*)p_val.data(),
      p_val.size());
  }

  auto set_option(FDBTransactionOption p_opt, std::optional<std::string_view> p_val) -> int {
    return p_val
      ? fdb_transaction_set_option(
          trans_,
          p_opt,
          reinterpret_cast<const uint8_t*>(p_val->data()),
          static_cast<int>(p_val->size()))
      : fdb_transaction_set_option(trans_, p_opt, nullptr, 0);
  }

 private:
  explicit s_fdb_trans(FDBTransaction* p_trans) : trans_(p_trans) {}
  void move_fn(s_fdb_trans& p_obj) {
    if (trans_) {
      fdb_transaction_destroy(trans_);
    }
    trans_ = std::exchange(p_obj.trans_, nullptr);
  }

  FDBTransaction* trans_ = nullptr;
};
// NOLINTEND

} // namespace sib::db

#endif // SIB_DB_FDB