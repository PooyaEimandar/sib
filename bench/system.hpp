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