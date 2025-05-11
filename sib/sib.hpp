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
#ifdef SIB_EXPORTS
#define SIB_API __declspec(dllexport)
#else
#define SIB_API __declspec(dllimport)
#endif
#else
#define SIB_API __attribute__((visibility("default")))
#endif

[[nodiscard]] SIB_API inline auto init(int p_argc, std::span<char *> p_argv)
  -> folly::Expected<folly::Unit, folly::fbstring> {
  if (p_argc <= 0 || p_argv.data() == nullptr) {
    return folly::makeUnexpected("sib::init invalid arguments");
  }
  auto *ptr = p_argv.data();
  std::ignore = folly::Init(&p_argc, &ptr, false);
  return folly::unit;
}
