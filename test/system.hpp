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

#include <gtest/gtest.h>
#include <sib/sib.hpp>

// NOLINTBEGIN (modernize-use-trailing-return-type)

using namespace sib::system;

TEST(WTraceTest, BasicTraceConstruction) {
  const int64_t code = 404;
  folly::fbstring msg = "Resource not found";

  s_trace trace(code, folly::fbstring(msg), "main.cpp", 42);

  EXPECT_EQ(trace.last_err_code(), code);
  EXPECT_EQ(trace.last_err_msg(), msg);
  EXPECT_NE(trace.to_std_string().find("main.cpp(42)"), std::string::npos);
}

TEST(WTraceTest, TraceFromErrc) {
  auto code = std::errc::timed_out;
  folly::fbstring msg = "Operation timed out";

  s_trace trace(code, folly::fbstring(msg), "timeout.cpp", 88);

  EXPECT_EQ(trace.last_err_code(), static_cast<int64_t>(std::make_error_code(code).value()));
  EXPECT_EQ(trace.last_err_msg(), msg);
  EXPECT_NE(trace.to_std_string().find("timeout.cpp(88)"), std::string::npos);
}