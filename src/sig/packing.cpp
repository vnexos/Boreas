/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file packing.cpp
 * @brief Triển khai việc đóng gói/mở gói mảng byte thành đa thức.
 */
#include "packing.hpp"

namespace Dilithium {

/* ================= Đóng gói đa thức ================= */

void polyEtaPack(uint8_t* r, const Polynomial* a)
{
  for (int i = 0; i < DILITHIUM_N / 8; ++i)
  {
    uint8_t t[8];
    t[0] = DILITHIUM_ETA - a->coeffs[8 * i + 0];
    t[1] = DILITHIUM_ETA - a->coeffs[8 * i + 1];
    t[2] = DILITHIUM_ETA - a->coeffs[8 * i + 2];
    t[3] = DILITHIUM_ETA - a->coeffs[8 * i + 3];
    t[4] = DILITHIUM_ETA - a->coeffs[8 * i + 4];
    t[5] = DILITHIUM_ETA - a->coeffs[8 * i + 5];
    t[6] = DILITHIUM_ETA - a->coeffs[8 * i + 6];
    t[7] = DILITHIUM_ETA - a->coeffs[8 * i + 7];

    r[3 * i + 0] = (t[0] >> 0) | (t[1] << 3) | (t[2] << 6);
    r[3 * i + 1] = (t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7);
    r[3 * i + 2] = (t[5] >> 1) | (t[6] << 2) | (t[7] << 5);
  }
}

void polyEtaUnpack(Polynomial* r, const uint8_t* a)
{
  for (int i = 0; i < DILITHIUM_N / 8; ++i)
  {
    r->coeffs[8 * i + 0] = (a[3 * i + 0] >> 0) & 7;
    r->coeffs[8 * i + 1] = (a[3 * i + 0] >> 3) & 7;
    r->coeffs[8 * i + 2] = ((a[3 * i + 0] >> 6) | (a[3 * i + 1] << 2)) & 7;
    r->coeffs[8 * i + 3] = (a[3 * i + 1] >> 1) & 7;
    r->coeffs[8 * i + 4] = (a[3 * i + 1] >> 4) & 7;
    r->coeffs[8 * i + 5] = ((a[3 * i + 1] >> 7) | (a[3 * i + 2] << 1)) & 7;
    r->coeffs[8 * i + 6] = (a[3 * i + 2] >> 2) & 7;
    r->coeffs[8 * i + 7] = (a[3 * i + 2] >> 5) & 7;

    r->coeffs[8 * i + 0] = DILITHIUM_ETA - r->coeffs[8 * i + 0];
    r->coeffs[8 * i + 1] = DILITHIUM_ETA - r->coeffs[8 * i + 1];
    r->coeffs[8 * i + 2] = DILITHIUM_ETA - r->coeffs[8 * i + 2];
    r->coeffs[8 * i + 3] = DILITHIUM_ETA - r->coeffs[8 * i + 3];
    r->coeffs[8 * i + 4] = DILITHIUM_ETA - r->coeffs[8 * i + 4];
    r->coeffs[8 * i + 5] = DILITHIUM_ETA - r->coeffs[8 * i + 5];
    r->coeffs[8 * i + 6] = DILITHIUM_ETA - r->coeffs[8 * i + 6];
    r->coeffs[8 * i + 7] = DILITHIUM_ETA - r->coeffs[8 * i + 7];
  }
}

void polyT1Pack(uint8_t* r, const Polynomial* a)
{
  for (int i = 0; i < DILITHIUM_N / 4; ++i)
  {
    r[5 * i + 0] = (a->coeffs[4 * i + 0] >> 0);
    r[5 * i + 1] = (a->coeffs[4 * i + 0] >> 8) | (a->coeffs[4 * i + 1] << 2);
    r[5 * i + 2] = (a->coeffs[4 * i + 1] >> 6) | (a->coeffs[4 * i + 2] << 4);
    r[5 * i + 3] = (a->coeffs[4 * i + 2] >> 4) | (a->coeffs[4 * i + 3] << 6);
    r[5 * i + 4] = (a->coeffs[4 * i + 3] >> 2);
  }
}

void polyT1Unpack(Polynomial* r, const uint8_t* a)
{
  for (int i = 0; i < DILITHIUM_N / 4; ++i)
  {
    r->coeffs[4 * i + 0] = ((a[5 * i + 0] >> 0) | ((uint32_t)a[5 * i + 1] << 8)) & 0x3FF;
    r->coeffs[4 * i + 1] = ((a[5 * i + 1] >> 2) | ((uint32_t)a[5 * i + 2] << 6)) & 0x3FF;
    r->coeffs[4 * i + 2] = ((a[5 * i + 2] >> 4) | ((uint32_t)a[5 * i + 3] << 4)) & 0x3FF;
    r->coeffs[4 * i + 3] = ((a[5 * i + 3] >> 6) | ((uint32_t)a[5 * i + 4] << 2)) & 0x3FF;
  }
}

void polyT0Pack(uint8_t* r, const Polynomial* a)
{
  uint32_t t[8];
  for (int i = 0; i < DILITHIUM_N / 8; ++i)
  {
    t[0] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 0];
    t[1] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 1];
    t[2] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 2];
    t[3] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 3];
    t[4] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 4];
    t[5] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 5];
    t[6] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 6];
    t[7] = (1 << (DILITHIUM_D - 1)) - a->coeffs[8 * i + 7];

    r[13 * i + 0]   = t[0];
    r[13 * i + 1]   = t[0] >> 8;
    r[13 * i + 1]  |= t[1] << 5;
    r[13 * i + 2]   = t[1] >> 3;
    r[13 * i + 3]   = t[1] >> 11;
    r[13 * i + 3]  |= t[2] << 2;
    r[13 * i + 4]   = t[2] >> 6;
    r[13 * i + 4]  |= t[3] << 7;
    r[13 * i + 5]   = t[3] >> 1;
    r[13 * i + 6]   = t[3] >> 9;
    r[13 * i + 6]  |= t[4] << 4;
    r[13 * i + 7]   = t[4] >> 4;
    r[13 * i + 8]   = t[4] >> 12;
    r[13 * i + 8]  |= t[5] << 1;
    r[13 * i + 9]   = t[5] >> 7;
    r[13 * i + 9]  |= t[6] << 6;
    r[13 * i + 10]  = t[6] >> 2;
    r[13 * i + 11]  = t[6] >> 10;
    r[13 * i + 11] |= t[7] << 3;
    r[13 * i + 12]  = t[7] >> 5;
  }
}

void polyT0Unpack(Polynomial* r, const uint8_t* a)
{
  for (int i = 0; i < DILITHIUM_N / 8; ++i)
  {
    r->coeffs[8 * i + 0]  = a[13 * i + 0];
    r->coeffs[8 * i + 0] |= (uint32_t)a[13 * i + 1] << 8;
    r->coeffs[8 * i + 0] &= 0x1FFF;

    r->coeffs[8 * i + 1]  = a[13 * i + 1] >> 5;
    r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 2] << 3;
    r->coeffs[8 * i + 1] |= (uint32_t)a[13 * i + 3] << 11;
    r->coeffs[8 * i + 1] &= 0x1FFF;

    r->coeffs[8 * i + 2]  = a[13 * i + 3] >> 2;
    r->coeffs[8 * i + 2] |= (uint32_t)a[13 * i + 4] << 6;
    r->coeffs[8 * i + 2] &= 0x1FFF;

    r->coeffs[8 * i + 3]  = a[13 * i + 4] >> 7;
    r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 5] << 1;
    r->coeffs[8 * i + 3] |= (uint32_t)a[13 * i + 6] << 9;
    r->coeffs[8 * i + 3] &= 0x1FFF;

    r->coeffs[8 * i + 4]  = a[13 * i + 6] >> 4;
    r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 7] << 4;
    r->coeffs[8 * i + 4] |= (uint32_t)a[13 * i + 8] << 12;
    r->coeffs[8 * i + 4] &= 0x1FFF;

    r->coeffs[8 * i + 5]  = a[13 * i + 8] >> 1;
    r->coeffs[8 * i + 5] |= (uint32_t)a[13 * i + 9] << 7;
    r->coeffs[8 * i + 5] &= 0x1FFF;

    r->coeffs[8 * i + 6]  = a[13 * i + 9] >> 6;
    r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 10] << 2;
    r->coeffs[8 * i + 6] |= (uint32_t)a[13 * i + 11] << 10;
    r->coeffs[8 * i + 6] &= 0x1FFF;

    r->coeffs[8 * i + 7]  = a[13 * i + 11] >> 3;
    r->coeffs[8 * i + 7] |= (uint32_t)a[13 * i + 12] << 5;
    r->coeffs[8 * i + 7] &= 0x1FFF;

    r->coeffs[8 * i + 0] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 0];
    r->coeffs[8 * i + 1] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 1];
    r->coeffs[8 * i + 2] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 2];
    r->coeffs[8 * i + 3] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 3];
    r->coeffs[8 * i + 4] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 4];
    r->coeffs[8 * i + 5] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 5];
    r->coeffs[8 * i + 6] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 6];
    r->coeffs[8 * i + 7] = (1 << (DILITHIUM_D - 1)) - r->coeffs[8 * i + 7];
  }
}

void polyZPack(uint8_t* r, const Polynomial* a)
{
  uint32_t t[2];
  for (int i = 0; i < DILITHIUM_N / 2; ++i)
  {
    t[0] = DILITHIUM_GAMMA1 - a->coeffs[2 * i + 0];
    t[1] = DILITHIUM_GAMMA1 - a->coeffs[2 * i + 1];

    r[5 * i + 0]  = t[0];
    r[5 * i + 1]  = t[0] >> 8;
    r[5 * i + 2]  = t[0] >> 16;
    r[5 * i + 2] |= t[1] << 4;
    r[5 * i + 3]  = t[1] >> 4;
    r[5 * i + 4]  = t[1] >> 12;
  }
}

void polyZUnpack(Polynomial* r, const uint8_t* a)
{
  for (int i = 0; i < DILITHIUM_N / 2; ++i)
  {
    r->coeffs[2 * i + 0]  = a[5 * i + 0];
    r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 1] << 8;
    r->coeffs[2 * i + 0] |= (uint32_t)a[5 * i + 2] << 16;
    r->coeffs[2 * i + 0] &= 0xFFFFF;

    r->coeffs[2 * i + 1]  = a[5 * i + 2] >> 4;
    r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 3] << 4;
    r->coeffs[2 * i + 1] |= (uint32_t)a[5 * i + 4] << 12;

    r->coeffs[2 * i + 0] = DILITHIUM_GAMMA1 - r->coeffs[2 * i + 0];
    r->coeffs[2 * i + 1] = DILITHIUM_GAMMA1 - r->coeffs[2 * i + 1];
  }
}

void polyW1Pack(uint8_t* r, const Polynomial* a)
{
  for (int i = 0; i < DILITHIUM_N / 2; ++i)
  {
    r[i] = a->coeffs[2 * i + 0] | (a->coeffs[2 * i + 1] << 4);
  }
}

/* ================= Đóng gói Khóa và Chữ ký ================= */

void packPublicKey(uint8_t pk[DILITHIUM_PUBLICKEYBYTES], const uint8_t rho[DILITHIUM_SEEDBYTES], const PolynomialVectorK* t1)
{
  for (int i = 0; i < DILITHIUM_SEEDBYTES; ++i)
  {
    pk[i] = rho[i];
  }
  pk += DILITHIUM_SEEDBYTES;
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    polyT1Pack(pk + i * DILITHIUM_POLYT1_PACKEDBYTES, &t1->vec[i]);
  }
}

void unpackPublicKey(uint8_t rho[DILITHIUM_SEEDBYTES], PolynomialVectorK* t1, const uint8_t pk[DILITHIUM_PUBLICKEYBYTES])
{
  for (int i = 0; i < DILITHIUM_SEEDBYTES; ++i)
  {
    rho[i] = pk[i];
  }
  pk += DILITHIUM_SEEDBYTES;
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    polyT1Unpack(&t1->vec[i], pk + i * DILITHIUM_POLYT1_PACKEDBYTES);
  }
}

void packSecretKey(uint8_t sk[DILITHIUM_SECRETKEYBYTES], const uint8_t rho[DILITHIUM_SEEDBYTES], const uint8_t tr[DILITHIUM_TRBYTES], const uint8_t key[DILITHIUM_SEEDBYTES], const PolynomialVectorK* t0, const PolynomialVectorL* s1, const PolynomialVectorK* s2)
{
  for (int i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    sk[i] = rho[i];
  sk += DILITHIUM_SEEDBYTES;

  for (int i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    sk[i] = key[i];
  sk += DILITHIUM_SEEDBYTES;

  for (int i = 0; i < DILITHIUM_TRBYTES; ++i)
    sk[i] = tr[i];
  sk += DILITHIUM_TRBYTES;

  for (int i = 0; i < DILITHIUM_L; ++i)
    polyEtaPack(sk + i * DILITHIUM_POLYETA_PACKEDBYTES, &s1->vec[i]);
  sk += DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

  for (int i = 0; i < DILITHIUM_K; ++i)
    polyEtaPack(sk + i * DILITHIUM_POLYETA_PACKEDBYTES, &s2->vec[i]);
  sk += DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

  for (int i = 0; i < DILITHIUM_K; ++i)
    polyT0Pack(sk + i * DILITHIUM_POLYT0_PACKEDBYTES, &t0->vec[i]);
}

void unpackSecretKey(uint8_t rho[DILITHIUM_SEEDBYTES], uint8_t tr[DILITHIUM_TRBYTES], uint8_t key[DILITHIUM_SEEDBYTES], PolynomialVectorK* t0, PolynomialVectorL* s1, PolynomialVectorK* s2, const uint8_t sk[DILITHIUM_SECRETKEYBYTES])
{
  for (int i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    rho[i] = sk[i];
  sk += DILITHIUM_SEEDBYTES;

  for (int i = 0; i < DILITHIUM_SEEDBYTES; ++i)
    key[i] = sk[i];
  sk += DILITHIUM_SEEDBYTES;

  for (int i = 0; i < DILITHIUM_TRBYTES; ++i)
    tr[i] = sk[i];
  sk += DILITHIUM_TRBYTES;

  for (int i = 0; i < DILITHIUM_L; ++i)
    polyEtaUnpack(&s1->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
  sk += DILITHIUM_L * DILITHIUM_POLYETA_PACKEDBYTES;

  for (int i = 0; i < DILITHIUM_K; ++i)
    polyEtaUnpack(&s2->vec[i], sk + i * DILITHIUM_POLYETA_PACKEDBYTES);
  sk += DILITHIUM_K * DILITHIUM_POLYETA_PACKEDBYTES;

  for (int i = 0; i < DILITHIUM_K; ++i)
    polyT0Unpack(&t0->vec[i], sk + i * DILITHIUM_POLYT0_PACKEDBYTES);
}

void packSignature(uint8_t sig[DILITHIUM_BYTES], const uint8_t c[DILITHIUM_CTILDEBYTES], const PolynomialVectorL* z, const PolynomialVectorK* h)
{
  for (int i = 0; i < DILITHIUM_CTILDEBYTES; ++i)
    sig[i] = c[i];
  sig += DILITHIUM_CTILDEBYTES;

  for (int i = 0; i < DILITHIUM_L; ++i)
    polyZPack(sig + i * DILITHIUM_POLYZ_PACKEDBYTES, &z->vec[i]);
  sig += DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

  for (int i = 0; i < DILITHIUM_POLYVECH_PACKEDBYTES; ++i)
    sig[i] = 0;

  int k = 0;
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    for (int j = 0; j < DILITHIUM_N; ++j)
    {
      if (h->vec[i].coeffs[j] != 0)
      {
        sig[k++] = j;
      }
    }
    sig[DILITHIUM_OMEGA + i] = k;
  }
}

int unpackSignature(uint8_t c[DILITHIUM_CTILDEBYTES], PolynomialVectorL* z, PolynomialVectorK* h, const uint8_t sig[DILITHIUM_BYTES])
{
  for (int i = 0; i < DILITHIUM_CTILDEBYTES; ++i)
    c[i] = sig[i];
  sig += DILITHIUM_CTILDEBYTES;

  for (int i = 0; i < DILITHIUM_L; ++i)
    polyZUnpack(&z->vec[i], sig + i * DILITHIUM_POLYZ_PACKEDBYTES);
  sig += DILITHIUM_L * DILITHIUM_POLYZ_PACKEDBYTES;

  int k = 0;
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    for (int j = 0; j < DILITHIUM_N; ++j)
      h->vec[i].coeffs[j] = 0;

    if (sig[DILITHIUM_OMEGA + i] < k || sig[DILITHIUM_OMEGA + i] > DILITHIUM_OMEGA) return 1;

    for (int j = k; j < sig[DILITHIUM_OMEGA + i]; ++j)
    {
      if (j > k && sig[j] <= sig[j - 1]) return 1;
      h->vec[i].coeffs[sig[j]] = 1;
    }
    k = sig[DILITHIUM_OMEGA + i];
  }

  for (int j = k; j < DILITHIUM_OMEGA; ++j)
  {
    if (sig[j]) return 1;
  }
  return 0;
}

} // namespace Dilithium
