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

#include <folly/small_vector.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <variant>

#include <sib/system/s_trace.hpp>

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

  [[nodiscard]] auto as_string_view() const -> boost::leaf::result<std::string_view> {
    if (type_ != s_buffer_type::TEXT) {
      return S_ERROR(std::errc::operation_canceled, "s_buffer is not of type TEXT");
    }

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
