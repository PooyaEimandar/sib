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

#include <folly/Benchmark.h>
#include <sib/system/s_buffer.hpp>
#include <sib/system/s_trace.hpp>

using namespace sib::system;

constexpr size_t TEST_SIZE = 512;
constexpr uint8_t FILL_VALUE = 42;

// Benchmark small buffer resize (below N)
BENCHMARK(s_buffer_resize_small) {
  s_buffer<1024> buf(s_buffer_type::TEXT);
  buf.resize(TEST_SIZE, FILL_VALUE);
}

// Benchmark resize that promotes to heap vector
BENCHMARK(s_buffer_resize_promote) {
  s_buffer<128> buf(s_buffer_type::TEXT);
  buf.resize(512, FILL_VALUE);
}

// Benchmark reset
BENCHMARK(s_buffer_reset) {
  s_buffer<1024> buf(s_buffer_type::TEXT);
  buf.resize(TEST_SIZE, FILL_VALUE);
  buf.reset();
}

// Benchmark as_string_view success
BENCHMARK(s_buffer_as_string_view_ok) {
  s_buffer<1024> buf(s_buffer_type::TEXT);
  buf.resize(TEST_SIZE, 'a');
  auto _ = buf.as_string_view();
}

// Benchmark as_string_view with embedded null
BENCHMARK(s_buffer_as_string_view_fail) {
  s_buffer<1024> buf(s_buffer_type::TEXT);
  buf.resize(TEST_SIZE, 'a');
  buf.data()[100] = '\0'; // Add null in the middle
  auto _ = buf.as_string_view();
}

BENCHMARK(TraceConstructor, iters) {
  while (iters--) {
    s_trace trace(404, "Not Found", __FILE__, __LINE__);
    folly::doNotOptimizeAway(trace);
  }
}

BENCHMARK(TracePushStack, iters) {
  s_trace trace;
  while (iters--) {
    trace.push(s_trace::s_stack(500, "Internal Error", __FILE__, __LINE__));
  }
  folly::doNotOptimizeAway(trace);
}

BENCHMARK(TraceMerge, iters) {
  s_trace base;
  s_trace other;
  other.push(s_trace::s_stack(123, "Child Trace", __FILE__, __LINE__));

  while (iters--) {
    s_trace temp = base;
    temp.merge(other);
    folly::doNotOptimizeAway(temp);
  }
}

BENCHMARK(TraceToString, iters) {
  s_trace trace;
  for (int i = 0; i < 10; ++i) {
    trace.push(
      s_trace::s_stack(100 + i, folly::to<folly::fbstring>("msg_", i), __FILE__, __LINE__));
  }

  while (iters--) {
    auto result = trace.to_std_string();
    folly::doNotOptimizeAway(result);
  }
}
