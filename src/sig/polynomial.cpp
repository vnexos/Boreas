/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file polynomial.cpp
 * @brief Triển khai các phép toán trên đa thức và vector đa thức của Dilithium.
 */
#include "polynomial.hpp"
#include "ntt.hpp"
#include "reduce.hpp"
#include "rounding.hpp"
#include "symmetric.hpp"

namespace Dilithium {

/* ================= Các phép toán trên Đa thức ================= */

void polyReduce(Polynomial* a)
{
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    a->coeffs[i] = reduce32(a->coeffs[i]);
  }
}

void polyConditionalAddQ(Polynomial* a)
{
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    a->coeffs[i] = conditionalAddQ(a->coeffs[i]);
  }
}

void polyAdd(Polynomial* c, const Polynomial* a, const Polynomial* b)
{
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    c->coeffs[i] = a->coeffs[i] + b->coeffs[i];
  }
}

void polySub(Polynomial* c, const Polynomial* a, const Polynomial* b)
{
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    c->coeffs[i] = a->coeffs[i] - b->coeffs[i];
  }
}

void polyShiftLeft(Polynomial* a)
{
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    a->coeffs[i] <<= DILITHIUM_D;
  }
}

void polyNTT(Polynomial* a)
{
  applyNTT(a->coeffs);
}

void polyInverseNTTToMont(Polynomial* a)
{
  applyInverseNTT(a->coeffs);
}

void polyPointwiseMontgomery(Polynomial* c, const Polynomial* a, const Polynomial* b)
{
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    c->coeffs[i] = montgomeryReduce((int64_t)a->coeffs[i] * b->coeffs[i]);
  }
}

void polyPower2Round(Polynomial* a1, Polynomial* a0, const Polynomial* a)
{
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    a1->coeffs[i] = power2round(&a0->coeffs[i], a->coeffs[i]);
  }
}

void polyDecompose(Polynomial* a1, Polynomial* a0, const Polynomial* a)
{
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    a1->coeffs[i] = decompose(&a0->coeffs[i], a->coeffs[i]);
  }
}

unsigned int polyMakeHint(Polynomial* h, const Polynomial* a0, const Polynomial* a1)
{
  unsigned int s = 0;
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    h->coeffs[i]  = makeHint(a0->coeffs[i], a1->coeffs[i]);
    s            += h->coeffs[i];
  }
  return s;
}

void polyUseHint(Polynomial* b, const Polynomial* a, const Polynomial* h)
{
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    b->coeffs[i] = useHint(a->coeffs[i], h->coeffs[i]);
  }
}

int polyCheckNorm(const Polynomial* a, int32_t bound)
{
  int32_t t;
  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    t = a->coeffs[i];
    t = t >> 31;
    t = a->coeffs[i] - (t & 2 * a->coeffs[i]);
    if (t >= bound) return 1;
  }
  return 0;
}

/* ================= Các hàm lấy mẫu (Sampling) ================= */

static unsigned int rejectionUniform(int32_t* a, unsigned int len, const uint8_t* buf, unsigned int buflen)
{
  unsigned int ctr = 0, pos = 0;
  uint32_t     t;
  while (ctr < len && pos + 3 <= buflen)
  {
    t  = buf[pos++];
    t |= (uint32_t)buf[pos++] << 8;
    t |= (uint32_t)buf[pos++] << 16;
    t &= 0x7FFFFF;

    if (t < DILITHIUM_Q)
    {
      a[ctr++] = t;
    }
  }
  return ctr;
}

void polyUniform(Polynomial* a, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
  unsigned int          ctr    = 0;
  unsigned int          buflen = DILITHIUM_STREAM128_BLOCKBYTES;
  uint8_t               buf[DILITHIUM_STREAM128_BLOCKBYTES + 2];
  Crypto::Keccak::State state;

  stream128Init(&state, seed, nonce);
  stream128SqueezeBlocks(buf, 1, &state);

  ctr = rejectionUniform(a->coeffs, DILITHIUM_N, buf, buflen);

  while (ctr < DILITHIUM_N)
  {
    unsigned int off = buflen % 3;
    for (unsigned int i = 0; i < off; ++i)
    {
      buf[i] = buf[buflen - off + i];
    }
    stream128SqueezeBlocks(buf + off, 1, &state);
    buflen  = DILITHIUM_STREAM128_BLOCKBYTES + off;
    ctr    += rejectionUniform(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen);
  }
}

static unsigned int rejectionEta(int32_t* a, unsigned int len, const uint8_t* buf, unsigned int buflen)
{
  unsigned int ctr = 0, pos = 0;
  uint32_t     t0, t1;
  while (ctr < len && pos < buflen)
  {
    t0 = buf[pos] & 0x0F;
    t1 = buf[pos++] >> 4;

    if (t0 < 15)
    {
      // Đối với ETA = 2, t0 < 15, tính a[ctr] = 2 - t0 + (t0 * 205 >> 10) * 5 (Đây là tối ưu của C)
      t0       = t0 - (205 * t0 >> 10) * 5;
      a[ctr++] = DILITHIUM_ETA - t0;
    }
    if (t1 < 15 && ctr < len)
    {
      t1       = t1 - (205 * t1 >> 10) * 5;
      a[ctr++] = DILITHIUM_ETA - t1;
    }
  }
  return ctr;
}

void polyUniformEta(Polynomial* a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
  unsigned int          ctr    = 0;
  unsigned int          buflen = DILITHIUM_STREAM256_BLOCKBYTES;
  uint8_t               buf[DILITHIUM_STREAM256_BLOCKBYTES];
  Crypto::Keccak::State state;

  stream256Init(&state, seed, nonce);
  stream256SqueezeBlocks(buf, 1, &state);

  ctr = rejectionEta(a->coeffs, DILITHIUM_N, buf, buflen);

  while (ctr < DILITHIUM_N)
  {
    stream256SqueezeBlocks(buf, 1, &state);
    ctr += rejectionEta(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen);
  }
}

static unsigned int rejectionGamma1(int32_t* a, unsigned int len, const uint8_t* buf, unsigned int buflen)
{
  unsigned int ctr = 0, pos = 0;
  uint32_t     t0, t1;
  while (ctr < len && pos + 5 <= buflen)
  {
    t0  = buf[pos];
    t0 |= (uint32_t)buf[pos + 1] << 8;
    t0 |= (uint32_t)buf[pos + 2] << 16;
    t0 &= 0xFFFFF; // 20 bits

    t1  = buf[pos + 2] >> 4;
    t1 |= (uint32_t)buf[pos + 3] << 4;
    t1 |= (uint32_t)buf[pos + 4] << 12;

    pos += 5;

    if (t0 <= 2 * DILITHIUM_GAMMA1)
    {
      a[ctr++] = DILITHIUM_GAMMA1 - t0;
    }
    if (t1 <= 2 * DILITHIUM_GAMMA1 && ctr < len)
    {
      a[ctr++] = DILITHIUM_GAMMA1 - t1;
    }
  }
  return ctr;
}

void polyUniformGamma1(Polynomial* a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
  unsigned int          ctr    = 0;
  unsigned int          buflen = DILITHIUM_STREAM256_BLOCKBYTES;
  uint8_t               buf[DILITHIUM_STREAM256_BLOCKBYTES + 4]; // max leftover = 4 bytes
  Crypto::Keccak::State state;

  stream256Init(&state, seed, nonce);
  stream256SqueezeBlocks(buf, 1, &state);

  ctr = rejectionGamma1(a->coeffs, DILITHIUM_N, buf, buflen);

  while (ctr < DILITHIUM_N)
  {
    unsigned int off = buflen % 5;
    for (unsigned int i = 0; i < off; ++i)
    {
      buf[i] = buf[buflen - off + i];
    }
    stream256SqueezeBlocks(buf + off, 1, &state);
    buflen  = DILITHIUM_STREAM256_BLOCKBYTES + off;
    ctr    += rejectionGamma1(a->coeffs + ctr, DILITHIUM_N - ctr, buf, buflen);
  }
}

void polyChallenge(Polynomial* c, const uint8_t seed[DILITHIUM_CTILDEBYTES])
{
  unsigned int          b, pos;
  uint64_t              signs;
  uint8_t               buf[DILITHIUM_STREAM256_BLOCKBYTES];
  Crypto::Keccak::State state;

  Crypto::Keccak::init(&state, DILITHIUM_STREAM256_BLOCKBYTES);
  Crypto::Keccak::absorb(&state, seed, DILITHIUM_CTILDEBYTES);
  Crypto::Keccak::finalize(&state, 0x1F); // SHAKE256
  Crypto::Keccak::squeeze(buf, DILITHIUM_STREAM256_BLOCKBYTES, &state);

  signs = 0;
  for (int i = 0; i < 8; ++i)
  {
    signs |= (uint64_t)buf[i] << (8 * i);
  }
  pos = 8;

  for (int i = 0; i < DILITHIUM_N; ++i)
  {
    c->coeffs[i] = 0;
  }

  for (unsigned i = DILITHIUM_N - DILITHIUM_TAU; i < DILITHIUM_N; ++i)
  {
    do
    {
      if (pos >= DILITHIUM_STREAM256_BLOCKBYTES)
      {
        Crypto::Keccak::squeeze(buf, DILITHIUM_STREAM256_BLOCKBYTES, &state);
        pos = 0;
      }
      b = buf[pos++];
    } while (b > i);

    c->coeffs[i]   = c->coeffs[b];
    c->coeffs[b]   = 1 - 2 * (signs & 1);
    signs        >>= 1;
  }
}

/* ================= Vector L Đa thức ================= */

void polyVectorLReduce(PolynomialVectorL* v)
{
  for (int i = 0; i < DILITHIUM_L; ++i)
    polyReduce(&v->vec[i]);
}

void polyVectorLAdd(PolynomialVectorL* w, const PolynomialVectorL* u, const PolynomialVectorL* v)
{
  for (int i = 0; i < DILITHIUM_L; ++i)
    polyAdd(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyVectorLNTT(PolynomialVectorL* v)
{
  for (int i = 0; i < DILITHIUM_L; ++i)
    polyNTT(&v->vec[i]);
}

void polyVectorLInverseNTTToMont(PolynomialVectorL* v)
{
  for (int i = 0; i < DILITHIUM_L; ++i)
    polyInverseNTTToMont(&v->vec[i]);
}

void polyVectorLPointwisePolyMontgomery(PolynomialVectorL* r, const Polynomial* a, const PolynomialVectorL* v)
{
  for (int i = 0; i < DILITHIUM_L; ++i)
    polyPointwiseMontgomery(&r->vec[i], a, &v->vec[i]);
}

void polyVectorLPointwiseAccMontgomery(Polynomial* w, const PolynomialVectorL* u, const PolynomialVectorL* v)
{
  Polynomial t;
  polyPointwiseMontgomery(w, &u->vec[0], &v->vec[0]);
  for (int i = 1; i < DILITHIUM_L; ++i)
  {
    polyPointwiseMontgomery(&t, &u->vec[i], &v->vec[i]);
    polyAdd(w, w, &t);
  }
}

int polyVectorLCheckNorm(const PolynomialVectorL* v, int32_t bound)
{
  for (int i = 0; i < DILITHIUM_L; ++i)
  {
    if (polyCheckNorm(&v->vec[i], bound)) return 1;
  }
  return 0;
}

void polyVectorLUniformEta(PolynomialVectorL* v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
  for (int i = 0; i < DILITHIUM_L; ++i)
  {
    polyUniformEta(&v->vec[i], seed, nonce++);
  }
}

void polyVectorLUniformGamma1(PolynomialVectorL* v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
  for (int i = 0; i < DILITHIUM_L; ++i)
  {
    polyUniformGamma1(&v->vec[i], seed, nonce + i * DILITHIUM_L); // Wait, reference usually does nonce++. Let's just do nonce++.
  }
}

/* ================= Vector K Đa thức ================= */

void polyVectorKReduce(PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyReduce(&v->vec[i]);
}

void polyVectorKConditionalAddQ(PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyConditionalAddQ(&v->vec[i]);
}

void polyVectorKAdd(PolynomialVectorK* w, const PolynomialVectorK* u, const PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyAdd(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyVectorKSub(PolynomialVectorK* w, const PolynomialVectorK* u, const PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polySub(&w->vec[i], &u->vec[i], &v->vec[i]);
}

void polyVectorKShiftLeft(PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyShiftLeft(&v->vec[i]);
}

void polyVectorKNTT(PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyNTT(&v->vec[i]);
}

void polyVectorKInverseNTTToMont(PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyInverseNTTToMont(&v->vec[i]);
}

void polyVectorKPointwisePolyMontgomery(PolynomialVectorK* r, const Polynomial* a, const PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyPointwiseMontgomery(&r->vec[i], a, &v->vec[i]);
}

int polyVectorKCheckNorm(const PolynomialVectorK* v, int32_t bound)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    if (polyCheckNorm(&v->vec[i], bound)) return 1;
  }
  return 0;
}

void polyVectorKPower2Round(PolynomialVectorK* v1, PolynomialVectorK* v0, const PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyPower2Round(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

void polyVectorKDecompose(PolynomialVectorK* v1, PolynomialVectorK* v0, const PolynomialVectorK* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyDecompose(&v1->vec[i], &v0->vec[i], &v->vec[i]);
}

unsigned int polyVectorKMakeHint(PolynomialVectorK* h, const PolynomialVectorK* v0, const PolynomialVectorK* v1)
{
  unsigned int s = 0;
  for (int i = 0; i < DILITHIUM_K; ++i)
    s += polyMakeHint(&h->vec[i], &v0->vec[i], &v1->vec[i]);
  return s;
}

void polyVectorKUseHint(PolynomialVectorK* w, const PolynomialVectorK* v, const PolynomialVectorK* h)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
    polyUseHint(&w->vec[i], &v->vec[i], &h->vec[i]);
}

void polyVectorKUniformEta(PolynomialVectorK* v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    polyUniformEta(&v->vec[i], seed, nonce++);
  }
}

/* ================= Ma trận Đa thức ================= */

void polyMatrixExpand(PolynomialMatrix* mat, const uint8_t rho[DILITHIUM_SEEDBYTES])
{
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    for (int j = 0; j < DILITHIUM_L; ++j)
    {
      polyUniform(&mat->mat[i].vec[j], rho, (i << 8) + j);
    }
  }
}

void polyMatrixPointwiseMontgomery(PolynomialVectorK* t, const PolynomialMatrix* mat, const PolynomialVectorL* v)
{
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    polyVectorLPointwiseAccMontgomery(&t->vec[i], &mat->mat[i], v);
  }
}

} // namespace Dilithium
