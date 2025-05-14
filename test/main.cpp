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

#ifdef SIB_BUILD_TEST

#include <gtest/gtest.h>
#include <sib/sib.hpp>

#include "database.hpp"
#include "network.hpp"
#include "system.hpp"

auto main(int p_argc, char **p_argv) -> int {
  std::span<char *> argv_span(p_argv, p_argc);
  const auto result = sib::init(p_argc, argv_span);
  assert(result.hasValue());

  testing::InitGoogleTest(&p_argc, p_argv);

  return RUN_ALL_TESTS();
}

#endif // SIB_BUILD_TEST
