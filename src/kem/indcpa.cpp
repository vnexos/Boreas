/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file indcpa.cpp
 * @brief Triển khai thuật toán PKE IND-CPA cốt lõi cho Kyber.
 */
#include "indcpa.hpp"
#include "ntt.hpp"
#include "polynomial.hpp"
#include <crypto/randombytes.hpp>
#include <crypto/sha3.hpp>

namespace Kyber {

static void polyVectorToBytes(uint8_t r[KYBER_POLYVECBYTES], const PolynomialVector* a)
{
  for (int i = 0; i < KYBER_K; i++)
  {
    polyToBytes(r + i * KYBER_POLYBYTES, &a->polynomials[i]);
  }
}

static void polyVectorFromBytes(PolynomialVector* r, const uint8_t a[KYBER_POLYVECBYTES])
{
  for (int i = 0; i < KYBER_K; i++)
  {
    polyFromBytes(&r->polynomials[i], a + i * KYBER_POLYBYTES);
  }
}

static void unpackSecretKey(PolynomialVector* sk, const uint8_t a[KYBER_INDCPA_SECKEYBYTES])
{
  polyVectorFromBytes(sk, a);
}

static void unpackPublicKey(PolynomialVector* pk, uint8_t seed[KYBER_SYMBYTES], const uint8_t a[KYBER_INDCPA_PUBKEYBYTES])
{
  polyVectorFromBytes(pk, a);
  for (int i = 0; i < KYBER_SYMBYTES; i++)
  {
    seed[i] = a[KYBER_POLYVECBYTES + i];
  }
}

void indcpaKeypair(uint8_t pk[KYBER_INDCPA_PUBKEYBYTES], uint8_t sk[KYBER_INDCPA_SECKEYBYTES])
{
  initZetas();

  uint8_t        buf[2 * KYBER_SYMBYTES];
  const uint8_t* publicSeed = buf;
  const uint8_t* noiseSeed  = buf + KYBER_SYMBYTES;

  uint8_t d[KYBER_SYMBYTES];
  Crypto::randombytes(d, KYBER_SYMBYTES);
  Crypto::SHA::sha512(buf, d, KYBER_SYMBYTES);

  PolynomialMatrix a;
  generateMatrixA(&a, publicSeed, false);

  PolynomialVector s, e;
  uint8_t          nonce = 0;

  for (int i = 0; i < KYBER_K; i++)
  {
    uint8_t prfBuf[KYBER_ETA1 * KYBER_N / 4];
    uint8_t extSeed[KYBER_SYMBYTES + 1];
    for (int j = 0; j < KYBER_SYMBYTES; j++)
      extSeed[j] = noiseSeed[j];
    extSeed[KYBER_SYMBYTES] = nonce++;
    Crypto::SHA::shake256(prfBuf, sizeof(prfBuf), extSeed, sizeof(extSeed));
    polyCBD(&s.polynomials[i], prfBuf);
  }

  for (int i = 0; i < KYBER_K; i++)
  {
    uint8_t prfBuf[KYBER_ETA1 * KYBER_N / 4];
    uint8_t extSeed[KYBER_SYMBYTES + 1];
    for (int j = 0; j < KYBER_SYMBYTES; j++)
      extSeed[j] = noiseSeed[j];
    extSeed[KYBER_SYMBYTES] = nonce++;
    Crypto::SHA::shake256(prfBuf, sizeof(prfBuf), extSeed, sizeof(extSeed));
    polyCBD(&e.polynomials[i], prfBuf);
  }

  polyVectorNTT(&s);
  polyVectorNTT(&e);

  PolynomialVector pkVec;
  for (int i = 0; i < KYBER_K; i++)
  {
    Polynomial temp;
    for (int j = 0; j < KYBER_N; j++)
      pkVec.polynomials[i].coefficients[j] = 0;

    for (int j = 0; j < KYBER_K; j++)
    {
      polyPointwiseMontgomery(&temp, &a.vectors[i].polynomials[j], &s.polynomials[j]);
      polyAdd(&pkVec.polynomials[i], &pkVec.polynomials[i], &temp);
    }

    polyToMont(&pkVec.polynomials[i]);
    polyAdd(&pkVec.polynomials[i], &pkVec.polynomials[i], &e.polynomials[i]);
    polyReduce(&pkVec.polynomials[i]);
  }

  polyVectorReduce(&s);
  polyVectorToBytes(sk, &s);
  polyVectorToBytes(pk, &pkVec);
  for (int i = 0; i < KYBER_SYMBYTES; i++)
    pk[KYBER_POLYVECBYTES + i] = publicSeed[i];
}

void indcpaEncrypt(uint8_t c[KYBER_INDCPA_BYTES], const uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t pk[KYBER_INDCPA_PUBKEYBYTES], const uint8_t coins[KYBER_SYMBYTES])
{
  initZetas();

  uint8_t          seed[KYBER_SYMBYTES];
  PolynomialVector pkVec;
  unpackPublicKey(&pkVec, seed, pk);

  PolynomialMatrix a;
  generateMatrixA(&a, seed, true); // Quá trình Encrypt dùng ma trận A chuyển vị

  PolynomialVector sp, ep;
  Polynomial       epp;

  uint8_t nonce = 0;
  for (int i = 0; i < KYBER_K; i++)
  {
    uint8_t prfBuf[KYBER_ETA1 * KYBER_N / 4];
    uint8_t extSeed[KYBER_SYMBYTES + 1];
    for (int j = 0; j < KYBER_SYMBYTES; j++)
      extSeed[j] = coins[j];
    extSeed[KYBER_SYMBYTES] = nonce++;
    Crypto::SHA::shake256(prfBuf, sizeof(prfBuf), extSeed, sizeof(extSeed));
    polyCBD(&sp.polynomials[i], prfBuf);
  }

  for (int i = 0; i < KYBER_K; i++)
  {
    uint8_t prfBuf[KYBER_ETA2 * KYBER_N / 4]; // Sử dụng ETA2 = 2 cho ep và epp (Kyber1024)
    uint8_t extSeed[KYBER_SYMBYTES + 1];
    for (int j = 0; j < KYBER_SYMBYTES; j++)
      extSeed[j] = coins[j];
    extSeed[KYBER_SYMBYTES] = nonce++;
    Crypto::SHA::shake256(prfBuf, sizeof(prfBuf), extSeed, sizeof(extSeed));
    polyCBD(&ep.polynomials[i], prfBuf);
  }

  {
    uint8_t prfBuf[KYBER_ETA2 * KYBER_N / 4];
    uint8_t extSeed[KYBER_SYMBYTES + 1];
    for (int j = 0; j < KYBER_SYMBYTES; j++)
      extSeed[j] = coins[j];
    extSeed[KYBER_SYMBYTES] = nonce++;
    Crypto::SHA::shake256(prfBuf, sizeof(prfBuf), extSeed, sizeof(extSeed));
    polyCBD(&epp, prfBuf);
  }

  polyVectorNTT(&sp);

  PolynomialVector bp;
  for (int i = 0; i < KYBER_K; i++)
  {
    Polynomial temp;
    for (int j = 0; j < KYBER_N; j++)
      bp.polynomials[i].coefficients[j] = 0;

    for (int j = 0; j < KYBER_K; j++)
    {
      polyPointwiseMontgomery(&temp, &a.vectors[i].polynomials[j], &sp.polynomials[j]);
      polyAdd(&bp.polynomials[i], &bp.polynomials[i], &temp);
    }
  }

  polyVectorInvNTT(&bp);
  polyVectorAdd(&bp, &bp, &ep);
  polyVectorReduce(&bp);

  Polynomial v;
  for (int j = 0; j < KYBER_N; j++)
    v.coefficients[j] = 0;

  for (int j = 0; j < KYBER_K; j++)
  {
    Polynomial temp;
    polyPointwiseMontgomery(&temp, &pkVec.polynomials[j], &sp.polynomials[j]);
    polyAdd(&v, &v, &temp);
  }

  polyInvNTT(&v);

  polyAdd(&v, &v, &epp);

  Polynomial msgPoly;
  polyFromMsg(&msgPoly, m);
  polyAdd(&v, &v, &msgPoly);
  polyReduce(&v);

  polyVectorCompress(c, &bp);
  polyCompress(c + KYBER_POLYVECCOMPRESSEDBYTES_DU, &v);
}

void indcpaDecrypt(uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t c[KYBER_INDCPA_BYTES], const uint8_t sk[KYBER_INDCPA_SECKEYBYTES])
{
  initZetas();

  PolynomialVector bp, skVec;
  Polynomial       v;

  polyVectorDecompress(&bp, c);
  polyDecompress(&v, c + KYBER_POLYVECCOMPRESSEDBYTES_DU);
  unpackSecretKey(&skVec, sk);

  polyVectorNTT(&bp);

  Polynomial mp;
  for (int j = 0; j < KYBER_N; j++)
    mp.coefficients[j] = 0;

  for (int j = 0; j < KYBER_K; j++)
  {
    Polynomial temp;
    polyPointwiseMontgomery(&temp, &skVec.polynomials[j], &bp.polynomials[j]);
    polyAdd(&mp, &mp, &temp);
  }

  polyInvNTT(&mp);
  polySub(&mp, &v, &mp);
  polyReduce(&mp);

  polyToMsg(m, &mp);
}

} // namespace Kyber
