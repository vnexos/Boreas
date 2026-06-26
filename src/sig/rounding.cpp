/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file rounding.cpp
 * @brief Triển khai thuật toán lấy bit cao/thấp và hint cho chữ ký Dilithium.
 */
#include "rounding.hpp"
#include "dilithium.hpp"

namespace Dilithium {

int32_t power2round(int32_t* a0, int32_t a)
{
  int32_t a1;

  a1  = (a + (1 << (DILITHIUM_D - 1)) - 1) >> DILITHIUM_D;
  *a0 = a - (a1 << DILITHIUM_D);
  return a1;
}

int32_t decompose(int32_t* a0, int32_t a)
{
  int32_t a1;

  a1 = (a + 127) >> 7;
#if DILITHIUM_GAMMA2 == ((DILITHIUM_Q - 1) / 32)
  a1  = (a1 * 1025 + (1 << 21)) >> 22;
  a1 &= 15;
#elif DILITHIUM_GAMMA2 == ((DILITHIUM_Q - 1) / 88)
  a1  = (a1 * 11275 + (1 << 23)) >> 24;
  a1 ^= ((43 - a1) >> 31) & a1;
#endif

  *a0  = a - a1 * 2 * DILITHIUM_GAMMA2;
  *a0 -= (((DILITHIUM_Q - 1) / 2 - *a0) >> 31) & DILITHIUM_Q;
  return a1;
}

unsigned int makeHint(int32_t a0, int32_t a1)
{
  if (a0 > DILITHIUM_GAMMA2 || a0 < -DILITHIUM_GAMMA2 || (a0 == -DILITHIUM_GAMMA2 && a1 != 0))
    return 1;

  return 0;
}

int32_t useHint(int32_t a, unsigned int hint)
{
  int32_t a0, a1;

  a1 = decompose(&a0, a);
  if (hint == 0)
    return a1;

#if DILITHIUM_GAMMA2 == ((DILITHIUM_Q - 1) / 32)
  if (a0 > 0)
    return (a1 + 1) & 15;
  else
    return (a1 - 1) & 15;
#elif DILITHIUM_GAMMA2 == ((DILITHIUM_Q - 1) / 88)
  if (a0 > 0)
    return (a1 == 43) ? 0 : a1 + 1;
  else
    return (a1 == 0) ? 43 : a1 - 1;
#endif
}

} // namespace Dilithium
