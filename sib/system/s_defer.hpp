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

#include <type_traits>
#include <utility>

template <typename F>
struct s_defer {
  explicit s_defer(F&& p_func) noexcept(std::is_nothrow_move_constructible_v<F>)
    : func_(std::move(p_func)) {}

  s_defer(s_defer&& p_other) noexcept(std::is_nothrow_move_constructible_v<F>)
    : func_(std::move(p_other.func_)) {}

  s_defer(const s_defer&) = delete;
  auto operator=(const s_defer&) -> s_defer& = delete;
  auto operator=(s_defer&& p_other) noexcept(std::is_nothrow_move_assignable_v<F>)
    -> s_defer& = delete;

  ~s_defer() noexcept { func_(); }

 private:
  F func_;
};

template <typename F>
[[nodiscard]] auto defer_ini(F&& p_func) noexcept(std::is_nothrow_constructible_v<F, F&&>) {
  return s_defer<F>(std::forward<F>(p_func));
}

// NOLINTBEGIN (cppcoreguidelines-macro-usage)
#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)
#define S_DEFER auto CONCAT(_defer_, __LINE__) = defer_ini
// NOLINTEND
