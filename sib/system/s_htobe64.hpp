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
