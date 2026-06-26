/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file reduce.cpp
 * @brief Triển khai thuật toán rút gọn Montgomery và Barrett của Dilithium.
 */
#include "reduce.hpp"
#include "dilithium.hpp"

namespace Dilithium {

int32_t montgomeryReduce(int64_t a)
{
  int32_t t;
  t = (int64_t)(int32_t)a * DILITHIUM_QINV;
  t = (a - (int64_t)t * DILITHIUM_Q) >> 32;
  return t;
}

int32_t reduce32(int32_t a)
{
  int32_t t;
  t = (a + (1 << 22)) >> 23;
  t = a - t * DILITHIUM_Q;
  return t;
}

int32_t conditionalAddQ(int32_t a)
{
  a += (a >> 31) & DILITHIUM_Q;
  return a;
}

int32_t freeze(int32_t a)
{
  a = reduce32(a);
  a = conditionalAddQ(a);
  return a;
}

} // namespace Dilithium
