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

#include <gtest/gtest.h>
#include <sib/system/s_trace.hpp>

// NOLINTBEGIN (modernize-use-trailing-return-type)

using w_trace = sib::system::w_trace;

TEST(WTraceTest, BasicTraceConstruction) {
  const int64_t code = 404;
  folly::fbstring msg = "Resource not found";

  w_trace trace(code, folly::fbstring(msg), "main.cpp", 42);

  EXPECT_EQ(trace.last_err_code(), code);
  EXPECT_EQ(trace.last_err_msg(), msg);
  EXPECT_NE(trace.to_std_string().find("main.cpp(42)"), std::string::npos);
}

TEST(WTraceTest, TraceFromErrc) {
  auto code = std::errc::timed_out;
  folly::fbstring msg = "Operation timed out";

  w_trace trace(code, folly::fbstring(msg), "timeout.cpp", 88);

  EXPECT_EQ(trace.last_err_code(), static_cast<int64_t>(std::make_error_code(code).value()));
  EXPECT_EQ(trace.last_err_msg(), msg);
  EXPECT_NE(trace.to_std_string().find("timeout.cpp(88)"), std::string::npos);
}

// NOLINTEND