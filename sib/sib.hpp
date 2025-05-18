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

#include <folly/Expected.h>
#include <folly/FBString.h>
#include <folly/Format.h>
#include <folly/init/Init.h>
#include <folly/io/IOBuf.h>

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
