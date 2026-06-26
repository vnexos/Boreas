/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file reduce.cpp
 * @brief Triển khai thuật toán rút gọn Montgomery và Barrett cho Kyber.
 */
#include "reduce.hpp"
#include "kyber.hpp"

namespace Kyber {

int16_t montgomeryReduce(int32_t a)
{
  int16_t t;
  t = (int16_t)a * KYBER_QINV;
  t = (a - (int32_t)t * KYBER_Q) >> 16;
  return t;
}

int16_t barrettReduce(int16_t a)
{
  int16_t       t;
  const int16_t v  = ((1 << 26) + KYBER_Q / 2) / KYBER_Q; // 20159
  t                = ((int32_t)v * a + (1 << 25)) >> 26;
  t               *= KYBER_Q;
  return a - t;
}

int16_t caddQ(int16_t a)
{
  a += (a >> 15) & KYBER_Q;
  return a;
}

} // namespace Kyber
