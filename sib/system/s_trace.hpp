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

#include <folly/Conv.h>
#include <folly/FBString.h>
#include <folly/String.h>

#include <boost/leaf.hpp>

#include <deque>
#include <sstream>
#include <string>
#include <thread>

namespace sib::system {

struct w_trace {
  struct s_stack {
    s_stack() noexcept = default;

    s_stack(
      int64_t p_err_code,
      folly::fbstring p_err_msg,
      folly::StringPiece p_source_file,
      int p_source_file_line) noexcept
      : thread_id_(std::this_thread::get_id()), err_code_(p_err_code),
        err_msg_(std::move(p_err_msg)), source_file_(p_source_file),
        source_file_line_(p_source_file_line) {}

    [[nodiscard]] auto err_code() const noexcept -> int64_t { return err_code_; }
    [[nodiscard]] auto err_msg() const noexcept -> const folly::fbstring& { return err_msg_; }

    friend auto operator<<(std::ostream& p_os, const s_stack& p_stack) -> std::ostream& {
      p_os << "|tid:" << p_stack.thread_id_ << "|code:" << p_stack.err_code_
           << "|msg:" << p_stack.err_msg_ << "|src:" << p_stack.source_file_ << "("
           << p_stack.source_file_line_ << ")\n";
      return p_os;
    }

   private:
    std::thread::id thread_id_;
    int64_t err_code_ = 0;
    folly::fbstring err_msg_;
    folly::StringPiece source_file_;
    int source_file_line_ = 0;
  };

  w_trace() noexcept = default;

  explicit w_trace(s_stack&& p_stack) { stacks_.emplace_front(std::move(p_stack)); }

  w_trace(int64_t p_code, folly::fbstring&& p_msg, folly::StringPiece p_file, int p_line) {
    stacks_.emplace_front(p_code, std::move(p_msg), p_file, p_line);
  }

  w_trace(std::errc p_code, folly::fbstring&& p_msg, folly::StringPiece p_file, int p_line) {
    stacks_.emplace_front(folly::to<int64_t>(p_code), std::move(p_msg), p_file, p_line);
  }

  [[nodiscard]] auto last_err_msg() const -> const folly::fbstring& {
    static const folly::fbstring EMPTY{};
    return stacks_.empty() ? EMPTY : stacks_.front().err_msg();
  }

  [[nodiscard]] auto last_err_code() const -> int64_t {
    return stacks_.empty() ? 0 : stacks_.front().err_code();
  }

  [[nodiscard]] auto stack() const -> const std::deque<s_stack>& { return stacks_; }

  void push(s_stack&& p_stack) { stacks_.emplace_front(std::move(p_stack)); }

  void merge(const w_trace& p_other) {
    stacks_.insert(stacks_.end(), p_other.stacks_.begin(), p_other.stacks_.end());
  }

  [[nodiscard]] auto to_std_string() const -> std::string {
    std::ostringstream oss;
    oss << "trace[frames=" << stacks_.size() << "]\n";
    for (const auto& frame : stacks_) {
      oss << "  " << frame;
    }
    return oss.str();
  }

  friend auto operator<<(std::ostream& p_os, const w_trace& p_trace) -> std::ostream& {
    for (const auto& iter : p_trace.stacks_) {
      p_os << iter;
    }
    return p_os;
  }

 private:
  std::deque<s_stack> stacks_;
};

} // namespace sib::system

// NOLINTBEGIN (readability-identifier-naming, cppcoreguidelines-macro-usage)
constexpr auto S_SUCCESS = 0;
#define S_ERROR(p_code, p_msg) \
  boost::leaf::new_error(sib::system::w_trace(p_code, p_msg, __FILE__, __LINE__))
// NOLINTEND
