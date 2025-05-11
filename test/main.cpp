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

#ifdef SIB_BUILD_TEST

#include <gtest/gtest.h>
#include <sib/sib.hpp>

#include "database.hpp"
#include "system.hpp"

auto main(int p_argc, char **p_argv) -> int {
  std::span<char *> argv_span(p_argv, p_argc);
  const auto result = init(p_argc, argv_span);
  assert(result.hasValue());

  testing::InitGoogleTest(&p_argc, p_argv);

  return RUN_ALL_TESTS();
}

#endif // SIB_BUILD_TEST
