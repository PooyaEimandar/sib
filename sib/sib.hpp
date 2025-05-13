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

#pragma once

#include <folly/Expected.h>
#include <folly/FBString.h>
#include <folly/Format.h>
#include <folly/init/Init.h>

#include <sib/system/s_defer.hpp>
#include <sib/system/s_trace.hpp>

#include <span>

#if defined(_WIN32) || defined(_WIN64)
#ifdef SIB_EXPORTS
#define SIB_API __declspec(dllexport)
#else
#define SIB_API __declspec(dllimport)
#endif
#else
#define SIB_API __attribute__((visibility("default")))
#endif

constexpr auto S_SUCCESS = 0;

// NOLINTBEGIN (readability-identifier-naming, cppcoreguidelines-macro-usage)
#define S_ERROR(p_code, p_msg) \
  folly::makeUnexpected(sib::system::s_trace(p_code, p_msg, __FILE__, __LINE__))

#define TRY_M(p_expr, p_msg)                                                           \
  ({                                                                                   \
    auto res = (p_expr);                                                               \
    if (res.hasError()) {                                                              \
      res.merge(sib::system::s_trace(res.last_err_code(), p_msg, __FILE__, __LINE__)); \
      return folly::makeUnexpected(res.error());                                       \
    }                                                                                  \
    std::move(res).value();                                                            \
  })

#define TRY_A(p_expr)                            \
  ({                                             \
    auto res = (p_expr);                         \
    if (res.hasError())                          \
      return folly::makeUnexpected(res.error()); \
    std::move(res).value();                      \
  })

#define TRY(p_expr)      \
  ({                     \
    auto res = (p_expr); \
    if (res.hasError())  \
      return;            \
  })

#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)
#define S_DEFER auto CONCAT(_defer_, __LINE__) = sib::system::defer_ini
// NOLINTEND

namespace sib {

template <typename T>
using s_result = folly::Expected<T, system::s_trace>;

[[nodiscard]] SIB_API inline auto init(int p_argc, std::span<char*> p_argv)
  -> s_result<folly::Unit> {
  if (p_argc <= 0 || p_argv.data() == nullptr) {
    return S_ERROR(std::errc::invalid_argument, "missing p_argc or p_argv");
  }

  auto* ptr = p_argv.data();
  try {
    std::ignore = folly::Init(&p_argc, &ptr, false);
  } catch (const std::exception& p_exc) {
    return S_ERROR(
      std::errc::operation_canceled,
      folly::sformat("folly::Init failed: because: {}", p_exc.what()));
  }
  return folly::unit;
}
} // namespace sib
