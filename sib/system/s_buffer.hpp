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

#include <folly/small_vector.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <variant>

#include <sib/sib.hpp>

namespace sib::system {

enum class s_buffer_type : std::uint8_t { BINARY = 0, TEXT };

using heap_less_vec = folly::small_vector<uint8_t>;
using heap_vec = std::vector<uint8_t>;

template <size_t N>
struct s_buffer {
  explicit s_buffer(s_buffer_type p_type) : type_(p_type) {}

  void reset() noexcept {
    std::visit([](auto& p_buf) { p_buf.clear(); }, buf_);
  }

  [[nodiscard]] auto data() const noexcept -> std::span<const uint8_t> {
    return std::visit(
      [](auto const& p_buf) { return std::span<const uint8_t>(p_buf.data(), p_buf.size()); }, buf_);
  }

  auto data() noexcept -> std::span<uint8_t> {
    return std::visit(
      [](auto& p_buf) { return std::span<uint8_t>(p_buf.data(), p_buf.size()); }, buf_);
  }

  [[nodiscard]] auto size() const noexcept -> size_t {
    return std::visit([](const auto& p_buf) { return p_buf.size(); }, buf_);
  }

  [[nodiscard]] auto capacity() noexcept -> size_t { return N; }

  [[nodiscard]] auto as_string_view() const -> s_result<std::string_view> {
    if (type_ != s_buffer_type::TEXT) {
      return S_ERROR(std::errc::operation_canceled, "s_buffer is not of type TEXT");
    }

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    std::string_view view(reinterpret_cast<const char*>(data().data()), size());
    // Check for null-terminator in the middle of the buffer
    if (view.find('\0') != std::string_view::npos) {
      return S_ERROR(std::errc::operation_canceled, "s_buffer contains embedded null byte");
    }

    return view;
  }

  void resize(size_t p_new_len, uint8_t p_fill_value) noexcept {
    std::visit(
      [&](auto& p_buf) {
        using Vec = std::decay_t<decltype(p_buf)>;
        if constexpr (std::is_same_v<Vec, heap_less_vec>) {
          if (p_new_len <= N) {
            p_buf.resize(p_new_len, p_fill_value);
          } else {
            heap_vec promoted(p_buf.begin(), p_buf.end());
            promoted.resize(p_new_len, p_fill_value);
            buf_ = std::move(promoted);
          }
        } else {
          p_buf.resize(p_new_len, p_fill_value);
        }
      },
      buf_);
  }

 private:
  s_buffer_type type_{s_buffer_type::BINARY};
  std::variant<heap_less_vec, heap_vec> buf_;
};

} // namespace sib::system
