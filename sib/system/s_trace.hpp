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

#include <folly/FBString.h>
#include <folly/String.h>

#include <deque>
#include <sstream>
#include <string>
#include <thread>

namespace sib::system {

struct s_trace {
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

  s_trace() noexcept = default;

  explicit s_trace(s_stack&& p_stack) { stacks_.emplace_front(std::move(p_stack)); }

  s_trace(int64_t p_code, folly::fbstring&& p_msg, folly::StringPiece p_file, int p_line) {
    stacks_.emplace_front(p_code, std::move(p_msg), p_file, p_line);
  }

  s_trace(std::errc p_code, folly::fbstring&& p_msg, folly::StringPiece p_file, int p_line) {
    stacks_.emplace_front(folly::to<int64_t>(p_code), std::move(p_msg), p_file, p_line);
  }

  [[nodiscard]] auto size() const -> size_t { return stacks_.size(); }

  [[nodiscard]] auto last_err_msg() const -> const folly::fbstring& {
    static const folly::fbstring EMPTY{};
    return stacks_.empty() ? EMPTY : stacks_.front().err_msg();
  }

  [[nodiscard]] auto last_err_code() const -> int64_t {
    return stacks_.empty() ? 0 : stacks_.front().err_code();
  }

  [[nodiscard]] auto stack() const -> const std::deque<s_stack>& { return stacks_; }

  void push(s_stack&& p_stack) { stacks_.emplace_front(std::move(p_stack)); }

  void merge(const s_trace& p_other) {
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

  friend auto operator<<(std::ostream& p_os, const s_trace& p_trace) -> std::ostream& {
    for (const auto& iter : p_trace.stacks_) {
      p_os << iter;
    }
    return p_os;
  }

 private:
  std::deque<s_stack> stacks_;
};

} // namespace sib::system
