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

#include <cstdint>
#include <type_traits>

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#elif defined(__linux__)
#include <endian.h>
#endif

namespace sib::system {

// NOLINTBEGIN (hicpp-signed-bitwise, readability-magic-numbers)
template <typename T>
constexpr auto htobe64(T p_value) noexcept -> T {
  constexpr auto INT_64_SIZE = 8;
  static_assert(
    std::is_integral_v<T> && sizeof(T) == INT_64_SIZE, "htobe64 requires a 64-bit integral type");

#if defined(__APPLE__)
  return static_cast<T>(OSSwapHostToBigInt64(static_cast<uint64_t>(p_value)));
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#if defined(__has_builtin)
#if __has_builtin(__builtin_bswap64)
  return static_cast<T>(__builtin_bswap64(static_cast<uint64_t>(p_value)));
#endif
#endif
  return static_cast<T>(
    (p_value & 0x00000000000000FFULL) << 56 | (p_value & 0x000000000000FF00ULL) << 40 |
    (p_value & 0x0000000000FF0000ULL) << 24 | (p_value & 0x00000000FF000000ULL) << 8 |
    (p_value & 0x000000FF00000000ULL) >> 8 | (p_value & 0x0000FF0000000000ULL) >> 24 |
    (p_value & 0x00FF000000000000ULL) >> 40 | (p_value & 0xFF00000000000000ULL) >> 56);
#else
  return p_value; // big endian already
#endif
}
// NOLINTEND

} // namespace sib::system
