/*
 * Copyright (c) WolfSource (https://github.com/wolfsource/wolf). All rights reserved.
 */

#pragma once

#include <folly/small_vector.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <variant>

#include <wolf/system/w_trace.hpp>

namespace wolf::system {

enum class w_buffer_type : std::uint8_t { BINARY = 0, TEXT };

using heap_less_vec = folly::small_vector<uint8_t>;
using heap_vec = std::vector<uint8_t>;

template <size_t N>
struct w_buffer {
  explicit w_buffer(w_buffer_type p_type) : type_(p_type) {}

  void reset() noexcept {
    std::visit([](auto& p_buf) { p_buf.clear(); }, buf_);
  }

  [[nodiscard]] auto data() const noexcept -> std::span<uint8_t> {
    return std::visit([](auto& p_buf) { return p_buf.data(); }, buf_);
  }

  auto data() noexcept -> std::span<uint8_t> {
    return std::visit([](auto& p_buf) { return p_buf.data(); }, buf_);
  }

  [[nodiscard]] auto size() noexcept -> size_t {
    return std::visit([](const auto& p_buf) { return p_buf.size(); }, buf_);
  }

  [[nodiscard]] auto capacity() noexcept -> size_t { return N; }

  [[nodiscard]] auto as_string_view() const -> boost::leaf::result<std::string_view> {
    if (type_ != w_buffer_type::TEXT) {
      return W_ERROR(std::errc::operation_canceled, "w_buffer is not of type TEXT");
    }

    std::string_view view(data(), size());
    // Check for null-terminator in the middle of the buffer
    if (view.find('\0') != std::string_view::npos) {
      return W_ERROR(std::errc::operation_canceled, "w_buffer contains embedded null byte");
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
  w_buffer_type type_{w_buffer_type::BINARY};
  std::variant<heap_less_vec, heap_vec> buf_;
};

} // namespace wolf::system
