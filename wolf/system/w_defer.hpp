/*
 * Copyright (c) WolfSource (https://github.com/wolfsource/wolf). All rights reserved.
 */

#pragma once

#include <type_traits>
#include <utility>

template <typename F>
struct w_defer {
  explicit w_defer(F&& p_func) noexcept(std::is_nothrow_move_constructible_v<F>)
    : func_(std::move(p_func)) {}

  w_defer(w_defer&& p_other) noexcept(std::is_nothrow_move_constructible_v<F>)
    : func_(std::move(p_other.func_)) {}

  w_defer(const w_defer&) = delete;
  auto operator=(const w_defer&) -> w_defer& = delete;
  auto operator=(w_defer&& p_other) noexcept(std::is_nothrow_move_assignable_v<F>)
    -> w_defer& = delete;

  ~w_defer() noexcept { func_(); }

 private:
  F func_;
};

template <typename F>
[[nodiscard]] auto defer_ini(F&& p_func) noexcept(std::is_nothrow_constructible_v<F, F&&>) {
  return w_defer<F>(std::forward<F>(p_func));
}

// NOLINTBEGIN (cppcoreguidelines-macro-usage)
#define CONCAT_IMPL(x, y) x##y
#define CONCAT(x, y) CONCAT_IMPL(x, y)
#define W_DEFER auto CONCAT(_defer_, __LINE__) = defer_ini
// NOLINTEND
