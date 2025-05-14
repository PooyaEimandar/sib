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

#include <type_traits>
#include <utility>

namespace sib::system {
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
  return sib::system::s_defer<F>(std::forward<F>(p_func));
}

} // namespace sib::system
