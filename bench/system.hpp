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
