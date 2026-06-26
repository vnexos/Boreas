/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file ntt.cpp
 * @brief Triển khai phép biến đổi Number Theoretic Transform (NTT) cho Kyber.
 */
#include "ntt.hpp"
#include "reduce.hpp"

namespace Kyber {

static const int16_t zetas[128] = {
    -1044, -758, -359, -1517, 1493, 1422, 287, 202,
    -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130,
    -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544,
    516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105,
    422, 587, 177, -235, -291, -460, 1574, 1653,
    -246, 778, 1159, -147, -777, 1483, -602, 1119,
    -1590, 644, -872, 349, 418, 329, -156, -75,
    817, 1097, 603, 610, 1322, -1285, -1465, 384,
    -1215, -136, 1218, -1335, -874, 220, -1187, -1659,
    -1185, -1530, -1278, 794, -1510, -854, -870, 478,
    -108, -308, 996, 991, 958, -1460, 1522, 1628};

void initZetas()
{
  // Do nothing, zetas is now a constant array
}

void applyNTT(int16_t r[256])
{
  int k = 1;
  for (int len = 128; len >= 2; len >>= 1)
  {
    for (int start = 0; start < 256; start = start + 2 * len)
    {
      int16_t zeta = zetas[k++];
      for (int j = start; j < start + len; j++)
      {
        int16_t t  = montgomeryReduce((int32_t)zeta * r[j + len]);
        r[j + len] = r[j] - t;
        r[j]       = r[j] + t;
      }
    }
  }
}

void applyInverseNTT(int16_t r[256])
{
  int k = 127;
  for (int len = 2; len <= 128; len <<= 1)
  {
    for (int start = 0; start < 256; start = start + 2 * len)
    {
      int16_t zeta = zetas[k--];
      for (int j = start; j < start + len; j++)
      {
        int16_t t  = r[j];
        r[j]       = barrettReduce(t + r[j + len]);
        r[j + len] = r[j + len] - t;
        int16_t w  = montgomeryReduce((int32_t)zeta * r[j + len]);
        r[j + len] = w;
      }
    }
  }

  // Nhân với f^-1 trong miền Montgomery
  // f = 128. f^-1 mod Q = 3303. Chuyển sang Montgomery: 3303 * 2^16 mod Q = 1441
  for (int j = 0; j < 256; j++)
  {
    r[j] = montgomeryReduce((int32_t)r[j] * 1441);
  }
}

static void baseMultiplication(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta)
{
  // a0*b0 + a1*b1*zeta
  int16_t r0  = montgomeryReduce((int32_t)a[1] * b[1]);
  r0          = montgomeryReduce((int32_t)r0 * zeta);
  r0         += montgomeryReduce((int32_t)a[0] * b[0]);

  // a0*b1 + a1*b0
  int16_t r1  = montgomeryReduce((int32_t)a[0] * b[1]);
  r1         += montgomeryReduce((int32_t)a[1] * b[0]);

  r[0] = r0;
  r[1] = r1;
}

void pointwiseMontgomery(int16_t r[256], const int16_t a[256], const int16_t b[256])
{
  for (int i = 0; i < 64; i++)
  {
    baseMultiplication(&r[4 * i], &a[4 * i], &b[4 * i], zetas[64 + i]);
    baseMultiplication(&r[4 * i + 2], &a[4 * i + 2], &b[4 * i + 2], -zetas[64 + i]);
  }
}

} // namespace Kyber
