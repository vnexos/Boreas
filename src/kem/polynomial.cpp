/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file polynomial.cpp
 * @brief Triển khai các phép toán trên đa thức và vector đa thức cho Kyber.
 */
#include "polynomial.hpp"
#include "ntt.hpp"
#include "reduce.hpp"
#include <crypto/sha3.hpp>

namespace Kyber {

void polyAdd(Polynomial* r, const Polynomial* a, const Polynomial* b)
{
  for (int i = 0; i < KYBER_N; i++)
  {
    r->coefficients[i] = a->coefficients[i] + b->coefficients[i];
  }
}

void polySub(Polynomial* r, const Polynomial* a, const Polynomial* b)
{
  for (int i = 0; i < KYBER_N; i++)
  {
    r->coefficients[i] = a->coefficients[i] - b->coefficients[i];
  }
}

void polyNTT(Polynomial* r)
{
  applyNTT(r->coefficients);
}

void polyInvNTT(Polynomial* r)
{
  applyInverseNTT(r->coefficients);
}

void polyPointwiseMontgomery(Polynomial* r, const Polynomial* a, const Polynomial* b)
{
  pointwiseMontgomery(r->coefficients, a->coefficients, b->coefficients);
}

void polyReduce(Polynomial* r)
{
  for (int i = 0; i < KYBER_N; i++)
  {
    r->coefficients[i] = barrettReduce(r->coefficients[i]);
  }
}

void polyCondSubQ(Polynomial* r)
{
  for (int i = 0; i < KYBER_N; i++)
  {
    r->coefficients[i] = caddQ(r->coefficients[i]);
  }
}

void polyToMont(Polynomial* r)
{
  const int16_t f = 1353; // (2^16)^2 mod 3329
  for (int i = 0; i < KYBER_N; i++)
  {
    r->coefficients[i] = montgomeryReduce((int32_t)r->coefficients[i] * f);
  }
}

void polyVectorAdd(PolynomialVector* r, const PolynomialVector* a, const PolynomialVector* b)
{
  for (int i = 0; i < KYBER_K; i++)
  {
    polyAdd(&r->polynomials[i], &a->polynomials[i], &b->polynomials[i]);
  }
}

void polyVectorNTT(PolynomialVector* r)
{
  for (int i = 0; i < KYBER_K; i++)
  {
    polyNTT(&r->polynomials[i]);
  }
}

void polyVectorInvNTT(PolynomialVector* r)
{
  for (int i = 0; i < KYBER_K; i++)
  {
    polyInvNTT(&r->polynomials[i]);
  }
}

void polyVectorPointwiseMontgomery(PolynomialVector* r, const PolynomialVector* a, const PolynomialVector* b)
{
  for (int i = 0; i < KYBER_K; i++)
  {
    polyPointwiseMontgomery(&r->polynomials[i], &a->polynomials[i], &b->polynomials[i]);
  }
}

void polyVectorReduce(PolynomialVector* r)
{
  for (int i = 0; i < KYBER_K; i++)
  {
    polyReduce(&r->polynomials[i]);
  }
}

void polyVectorCondSubQ(PolynomialVector* r)
{
  for (int i = 0; i < KYBER_K; i++)
  {
    polyCondSubQ(&r->polynomials[i]);
  }
}

void polyToBytes(uint8_t r[KYBER_POLYBYTES], const Polynomial* a)
{
  for (int i = 0; i < KYBER_N / 2; i++)
  {
    int16_t t0   = a->coefficients[2 * i];
    int16_t t1   = a->coefficients[2 * i + 1];
    t0           = caddQ(t0);
    t1           = caddQ(t1);
    r[3 * i + 0] = t0 & 0xFF;
    r[3 * i + 1] = (t0 >> 8) | ((t1 & 0x0F) << 4);
    r[3 * i + 2] = t1 >> 4;
  }
}

void polyFromBytes(Polynomial* r, const uint8_t a[KYBER_POLYBYTES])
{
  for (int i = 0; i < KYBER_N / 2; i++)
  {
    r->coefficients[2 * i]     = a[3 * i + 0] | ((uint16_t)(a[3 * i + 1] & 0x0F) << 8);
    r->coefficients[2 * i + 1] = (a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4);
  }
}

void polyToMsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const Polynomial* a)
{
  for (int i = 0; i < KYBER_N / 8; i++)
  {
    msg[i] = 0;
    for (int j = 0; j < 8; j++)
    {
      int16_t t  = a->coefficients[8 * i + j];
      t          = caddQ(t);
      t          = (((t << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
      msg[i]    |= t << j;
    }
  }
}

void polyFromMsg(Polynomial* r, const uint8_t msg[KYBER_INDCPA_MSGBYTES])
{
  for (int i = 0; i < KYBER_N / 8; i++)
  {
    for (int j = 0; j < 8; j++)
    {
      int mask                   = -(int)((msg[i] >> j) & 1);
      r->coefficients[8 * i + j] = mask & ((KYBER_Q + 1) / 2);
    }
  }
}

void polyCompress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_DV], const Polynomial* a)
{
  for (int i = 0; i < 32; i++)
  {
    uint8_t t[8];
    for (int j = 0; j < 8; j++)
    {
      uint32_t c = caddQ(a->coefficients[8 * i + j]);
      t[j]       = (((c << 5) + KYBER_Q / 2) / KYBER_Q) & 31;
    }
    r[5 * i + 0] = t[0] | (t[1] << 5);
    r[5 * i + 1] = (t[1] >> 3) | (t[2] << 2) | (t[3] << 7);
    r[5 * i + 2] = (t[3] >> 1) | (t[4] << 4);
    r[5 * i + 3] = (t[4] >> 4) | (t[5] << 1) | (t[6] << 6);
    r[5 * i + 4] = (t[6] >> 2) | (t[7] << 3);
  }
}

void polyDecompress(Polynomial* r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_DV])
{
  for (int i = 0; i < 32; i++)
  {
    uint8_t t[8];
    t[0] = a[5 * i + 0] & 31;
    t[1] = (a[5 * i + 0] >> 5) | ((a[5 * i + 1] & 3) << 3);
    t[2] = (a[5 * i + 1] >> 2) & 31;
    t[3] = (a[5 * i + 1] >> 7) | ((a[5 * i + 2] & 15) << 1);
    t[4] = (a[5 * i + 2] >> 4) | ((a[5 * i + 3] & 1) << 4);
    t[5] = (a[5 * i + 3] >> 1) & 31;
    t[6] = (a[5 * i + 3] >> 6) | ((a[5 * i + 4] & 7) << 2);
    t[7] = a[5 * i + 4] >> 3;
    for (int j = 0; j < 8; j++)
    {
      r->coefficients[8 * i + j] = ((uint32_t)t[j] * KYBER_Q + 16) >> 5;
    }
  }
}

static void poly11Compress(uint8_t r[352], const Polynomial* a)
{
  for (int i = 0; i < 32; i++)
  {
    uint16_t t[8];
    for (int j = 0; j < 8; j++)
    {
      uint32_t c = caddQ(a->coefficients[8 * i + j]);
      t[j]       = (((c << 11) + KYBER_Q / 2) / KYBER_Q) & 0x7FF;
    }
    r[11 * i + 0]  = t[0];
    r[11 * i + 1]  = (t[0] >> 8) | (t[1] << 3);
    r[11 * i + 2]  = (t[1] >> 5) | (t[2] << 6);
    r[11 * i + 3]  = t[2] >> 2;
    r[11 * i + 4]  = (t[2] >> 10) | (t[3] << 1);
    r[11 * i + 5]  = (t[3] >> 7) | (t[4] << 4);
    r[11 * i + 6]  = (t[4] >> 4) | (t[5] << 7);
    r[11 * i + 7]  = t[5] >> 1;
    r[11 * i + 8]  = (t[5] >> 9) | (t[6] << 2);
    r[11 * i + 9]  = (t[6] >> 6) | (t[7] << 5);
    r[11 * i + 10] = t[7] >> 3;
  }
}

static void poly11Decompress(Polynomial* r, const uint8_t a[352])
{
  for (int i = 0; i < 32; i++)
  {
    uint16_t t[8];
    t[0] = a[11 * i + 0] | ((uint16_t)(a[11 * i + 1] & 7) << 8);
    t[1] = (a[11 * i + 1] >> 3) | ((uint16_t)(a[11 * i + 2] & 0x3F) << 5);
    t[2] = (a[11 * i + 2] >> 6) | ((uint16_t)a[11 * i + 3] << 2) | ((uint16_t)(a[11 * i + 4] & 1) << 10);
    t[3] = (a[11 * i + 4] >> 1) | ((uint16_t)(a[11 * i + 5] & 0x0F) << 7);
    t[4] = (a[11 * i + 5] >> 4) | ((uint16_t)(a[11 * i + 6] & 0x7F) << 4);
    t[5] = (a[11 * i + 6] >> 7) | ((uint16_t)a[11 * i + 7] << 1) | ((uint16_t)(a[11 * i + 8] & 3) << 9);
    t[6] = (a[11 * i + 8] >> 2) | ((uint16_t)(a[11 * i + 9] & 0x1F) << 6);
    t[7] = (a[11 * i + 9] >> 5) | ((uint16_t)a[11 * i + 10] << 3);
    for (int j = 0; j < 8; j++)
    {
      r->coefficients[8 * i + j] = ((uint32_t)t[j] * KYBER_Q + 1024) >> 11;
    }
  }
}

void polyVectorCompress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES_DU], const PolynomialVector* a)
{
  for (int i = 0; i < KYBER_K; i++)
  {
    poly11Compress(r + i * 352, &a->polynomials[i]);
  }
}

void polyVectorDecompress(PolynomialVector* r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES_DU])
{
  for (int i = 0; i < KYBER_K; i++)
  {
    poly11Decompress(&r->polynomials[i], a + i * 352);
  }
}

void polyUniform(Polynomial* r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce1, uint8_t nonce2)
{
  uint8_t extSeed[34];
  for (int i = 0; i < KYBER_SYMBYTES; i++)
    extSeed[i] = seed[i];
  extSeed[KYBER_SYMBYTES]     = nonce1;
  extSeed[KYBER_SYMBYTES + 1] = nonce2;

  Crypto::Keccak::State state;
  Crypto::Keccak::init(&state, 168); // SHAKE128
  Crypto::Keccak::absorb(&state, extSeed, 34);
  Crypto::Keccak::finalize(&state, 0x1F);

  int count = 0;
  while (count < KYBER_N)
  {
    uint8_t chunk[2];
    Crypto::Keccak::squeeze(chunk, 2, &state);
    uint16_t val = chunk[0] | ((uint16_t)chunk[1] << 8);
    if (val < KYBER_Q)
    {
      r->coefficients[count++] = val;
    }
  }
}

void polyCBD(Polynomial* r, const uint8_t buf[KYBER_ETA1 * KYBER_N / 4])
{
  // ETA1 = 2 cho Kyber1024
  for (int i = 0; i < KYBER_N / 8; i++)
  {
    uint32_t t  = buf[4 * i + 0] | ((uint32_t)buf[4 * i + 1] << 8) | ((uint32_t)buf[4 * i + 2] << 16) | ((uint32_t)buf[4 * i + 3] << 24);
    uint32_t d  = t & 0x55555555;
    d          += (t >> 1) & 0x55555555;
    for (int j = 0; j < 8; j++)
    {
      int16_t a                  = (d >> (4 * j)) & 0x3;
      int16_t b                  = (d >> (4 * j + 2)) & 0x3;
      r->coefficients[8 * i + j] = a - b;
    }
  }
}

void generateMatrixA(PolynomialMatrix* matrixA, const uint8_t seed[KYBER_SYMBYTES], bool transposed)
{
  for (int i = 0; i < KYBER_K; i++)
  {
    for (int j = 0; j < KYBER_K; j++)
    {
      if (transposed)
      {
        polyUniform(&matrixA->vectors[i].polynomials[j], seed, i, j);
      } else
      {
        polyUniform(&matrixA->vectors[i].polynomials[j], seed, j, i);
      }
    }
  }
}

} // namespace Kyber
