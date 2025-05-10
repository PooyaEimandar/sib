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
#include <folly/Unit.h>
#include <folly/init/Init.h>

#include <cwchar>
#include <array>
#include <span>
#include <string>
#include <tuple>

#if defined(_WIN32) || defined(_WIN64)
#ifdef WOLF_EXPORTS
#define WOLF_API __declspec(dllexport)
#else
#define WOLF_API __declspec(dllimport)
#endif
#else
#define WOLF_API __attribute__((visibility("default")))
#endif

[[nodiscard]] WOLF_API inline auto init(int p_argc, std::span<char *> p_argv)
  -> folly::Expected<folly::Unit, folly::fbstring> {
  if (p_argc <= 0 || p_argv.data() == nullptr) {
    return folly::makeUnexpected("wolf::init: invalid arguments");
  }
  auto *ptr = p_argv.data();
  std::ignore = folly::Init(&p_argc, &ptr, false);
  return folly::unit;
}

#ifdef WOLF_BUILD_TEST
#include <gtest/gtest.h>

// NOLINTBEGIN (modernize-use-trailing-return-type)
TEST(WolfInitTest, RunsWithoutCrash) {
  constexpr int kArgc = 1;
  constexpr char kArg0[] = "wolf_test_app";
  std::array<char *, 2> argv = {const_cast<char *>(kArg0), nullptr};
  std::span<char *> argvSpan(argv.data(), kArgc);

  const auto result = init(kArgc, argvSpan);
  ASSERT_TRUE(result.hasValue()) << result.error();
}
// NOLINTEND
#endif
