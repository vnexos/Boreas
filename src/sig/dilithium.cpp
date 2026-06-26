/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file dilithium.cpp
 * @brief Triển khai logic sinh khóa, ký và xác minh của Dilithium.
 */
#include "dilithium.hpp"
#include "packing.hpp"
#include "polynomial.hpp"
#include "symmetric.hpp"
#include <crypto/randombytes.hpp>
#include <crypto/sha3.hpp>

namespace Dilithium {

void generateKeyPair(
    uint8_t publicKey[DILITHIUM_PUBLICKEYBYTES],
    uint8_t secretKey[DILITHIUM_SECRETKEYBYTES])
{
  uint8_t           seedbuf[2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES];
  uint8_t           tr[DILITHIUM_TRBYTES];
  const uint8_t *   rho, *rhoprime, *key;
  PolynomialMatrix  mat;
  PolynomialVectorL s1, s1hat;
  PolynomialVectorK s2, t1, t0;

  /* Lấy dữ liệu ngẫu nhiên cho rho, rhoprime và key */
  Crypto::randombytes(seedbuf, DILITHIUM_SEEDBYTES);
  seedbuf[DILITHIUM_SEEDBYTES + 0] = DILITHIUM_K;
  seedbuf[DILITHIUM_SEEDBYTES + 1] = DILITHIUM_L;

  Crypto::SHA::shake256(seedbuf, 2 * DILITHIUM_SEEDBYTES + DILITHIUM_CRHBYTES, seedbuf, DILITHIUM_SEEDBYTES + 2);
  rho      = seedbuf;
  rhoprime = rho + DILITHIUM_SEEDBYTES;
  key      = rhoprime + DILITHIUM_CRHBYTES;

  /* Mở rộng ma trận A từ rho */
  polyMatrixExpand(&mat, rho);

  /* Lấy mẫu các vector ngắn s1 và s2 */
  polyVectorLUniformEta(&s1, rhoprime, 0);
  polyVectorKUniformEta(&s2, rhoprime, DILITHIUM_L);

  /* Nhân ma trận với vector: t = A * s1 */
  s1hat = s1;
  polyVectorLNTT(&s1hat);
  polyMatrixPointwiseMontgomery(&t1, &mat, &s1hat);
  polyVectorKReduce(&t1);
  polyVectorKInverseNTTToMont(&t1);

  /* Cộng thêm vector lỗi s2: t = A * s1 + s2 */
  polyVectorKAdd(&t1, &t1, &s2);

  /* Tách t thành t1 và t0 */
  polyVectorKConditionalAddQ(&t1);
  polyVectorKPower2Round(&t1, &t0, &t1);
  packPublicKey(publicKey, rho, &t1);

  /* Tính hash H(rho, t1) làm giá trị tr và đóng gói khóa bí mật */
  Crypto::SHA::shake256(tr, DILITHIUM_TRBYTES, publicKey, DILITHIUM_PUBLICKEYBYTES);
  packSecretKey(secretKey, rho, tr, key, &t0, &s1, &s2);
}

void sign(
    uint8_t        signature[DILITHIUM_BYTES],
    size_t*        signatureLength,
    const uint8_t* message,
    size_t         messageLength,
    const uint8_t  secretKey[DILITHIUM_SECRETKEYBYTES])
{
  uint8_t               seedbuf[2 * DILITHIUM_SEEDBYTES + DILITHIUM_TRBYTES + 2 * DILITHIUM_CRHBYTES];
  uint8_t *             rho, *tr, *key, *mu, *rhoprime;
  uint16_t              nonce = 0;
  PolynomialMatrix      mat;
  PolynomialVectorL     s1, y, z;
  PolynomialVectorK     t0, s2, w1, w0, h;
  Polynomial            cp;
  Crypto::Keccak::State state;

  rho      = seedbuf;
  tr       = rho + DILITHIUM_SEEDBYTES;
  key      = tr + DILITHIUM_TRBYTES;
  mu       = key + DILITHIUM_SEEDBYTES;
  rhoprime = mu + DILITHIUM_CRHBYTES;
  unpackSecretKey(rho, tr, key, &t0, &s1, &s2, secretKey);

  /* Tiền tố mặc định của bản gốc (ctxlen = 0) */
  uint8_t pre[2] = {0, 0};

  /* Tính mu = CRH(tr, pre, msg) */
  Crypto::Keccak::init(&state, DILITHIUM_STREAM256_BLOCKBYTES);
  Crypto::Keccak::absorb(&state, tr, DILITHIUM_TRBYTES);
  Crypto::Keccak::absorb(&state, pre, 2);
  Crypto::Keccak::absorb(&state, message, messageLength);
  Crypto::Keccak::finalize(&state, 0x1F); // 0x1F = SHAKE
  Crypto::Keccak::squeeze(mu, DILITHIUM_CRHBYTES, &state);

  /* Sinh giá trị ngẫu nhiên rnd (bắt buộc theo chuẩn ngẫu nhiên) */
  uint8_t rnd[DILITHIUM_RNDBYTES];
  Crypto::randombytes(rnd, DILITHIUM_RNDBYTES);

  /* Tính rhoprime = CRH(key, rnd, mu) */
  Crypto::Keccak::init(&state, DILITHIUM_STREAM256_BLOCKBYTES);
  Crypto::Keccak::absorb(&state, key, DILITHIUM_SEEDBYTES);
  Crypto::Keccak::absorb(&state, rnd, DILITHIUM_RNDBYTES);
  Crypto::Keccak::absorb(&state, mu, DILITHIUM_CRHBYTES);
  Crypto::Keccak::finalize(&state, 0x1F);
  Crypto::Keccak::squeeze(rhoprime, DILITHIUM_CRHBYTES, &state);

  /* Khởi tạo ma trận A và chuyển s1, s2, t0 sang miền NTT */
  polyMatrixExpand(&mat, rho);
  polyVectorLNTT(&s1);
  polyVectorKNTT(&s2);
  polyVectorKNTT(&t0);

  unsigned int n;

rej:
  /* Lấy mẫu y */
  polyVectorLUniformGamma1(&y, rhoprime, nonce++);

  /* Tính w = A * y */
  z = y;
  polyVectorLNTT(&z);
  polyMatrixPointwiseMontgomery(&w1, &mat, &z);
  polyVectorKReduce(&w1);
  polyVectorKInverseNTTToMont(&w1);

  /* Phân rã w và gọi random oracle để tính challenge c */
  polyVectorKConditionalAddQ(&w1);
  polyVectorKDecompose(&w1, &w0, &w1);

  uint8_t w1_packed[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES];
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    polyW1Pack(w1_packed + i * DILITHIUM_POLYW1_PACKEDBYTES, &w1.vec[i]);
  }

  Crypto::Keccak::init(&state, DILITHIUM_STREAM256_BLOCKBYTES);
  Crypto::Keccak::absorb(&state, mu, DILITHIUM_CRHBYTES);
  Crypto::Keccak::absorb(&state, w1_packed, DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
  Crypto::Keccak::finalize(&state, 0x1F);

  uint8_t c[DILITHIUM_CTILDEBYTES];
  Crypto::Keccak::squeeze(c, DILITHIUM_CTILDEBYTES, &state);

  polyChallenge(&cp, c);
  polyNTT(&cp);

  /* Tính z = y + c * s1 và kiểm tra ràng buộc */
  polyVectorLPointwisePolyMontgomery(&z, &cp, &s1);
  polyVectorLInverseNTTToMont(&z);
  polyVectorLAdd(&z, &z, &y);
  polyVectorLReduce(&z);
  if (polyVectorLCheckNorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA))
  {
    goto rej;
  }

  /* Kiểm tra h và w0 */
  polyVectorKPointwisePolyMontgomery(&h, &cp, &s2);
  polyVectorKInverseNTTToMont(&h);
  polyVectorKSub(&w0, &w0, &h);
  polyVectorKReduce(&w0);
  if (polyVectorKCheckNorm(&w0, DILITHIUM_GAMMA2 - DILITHIUM_BETA))
  {
    goto rej;
  }

  /* Tạo hints cho w1 */
  polyVectorKPointwisePolyMontgomery(&h, &cp, &t0);
  polyVectorKInverseNTTToMont(&h);
  polyVectorKReduce(&h);
  if (polyVectorKCheckNorm(&h, DILITHIUM_GAMMA2))
  {
    goto rej;
  }

  polyVectorKAdd(&w0, &w0, &h);
  n = polyVectorKMakeHint(&h, &w0, &w1);
  if (n > DILITHIUM_OMEGA)
  {
    goto rej;
  }

  /* Đóng gói chữ ký */
  packSignature(signature, c, &z, &h);
  *signatureLength = DILITHIUM_BYTES;
}

bool verify(
    const uint8_t  signature[DILITHIUM_BYTES],
    size_t         signatureLength,
    const uint8_t* message,
    size_t         messageLength,
    const uint8_t  publicKey[DILITHIUM_PUBLICKEYBYTES])
{
  if (signatureLength != DILITHIUM_BYTES)
  {
    return false;
  }

  uint8_t               buf[DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES];
  uint8_t               rho[DILITHIUM_SEEDBYTES];
  uint8_t               mu[DILITHIUM_CRHBYTES];
  uint8_t               c[DILITHIUM_CTILDEBYTES];
  uint8_t               c2[DILITHIUM_CTILDEBYTES];
  Polynomial            cp;
  PolynomialMatrix      mat;
  PolynomialVectorL     z;
  PolynomialVectorK     t1, w1, h;
  Crypto::Keccak::State state;

  unpackPublicKey(rho, &t1, publicKey);

  if (unpackSignature(c, &z, &h, signature))
  {
    return false;
  }

  if (polyVectorLCheckNorm(&z, DILITHIUM_GAMMA1 - DILITHIUM_BETA))
  {
    return false;
  }

  /* Tính CRH(H(rho, t1), pre, msg) */
  Crypto::SHA::shake256(mu, DILITHIUM_TRBYTES, publicKey, DILITHIUM_PUBLICKEYBYTES);

  uint8_t pre[2] = {0, 0};
  Crypto::Keccak::init(&state, DILITHIUM_STREAM256_BLOCKBYTES);
  Crypto::Keccak::absorb(&state, mu, DILITHIUM_TRBYTES);
  Crypto::Keccak::absorb(&state, pre, 2);
  Crypto::Keccak::absorb(&state, message, messageLength);
  Crypto::Keccak::finalize(&state, 0x1F);
  Crypto::Keccak::squeeze(mu, DILITHIUM_CRHBYTES, &state);

  /* Tính w1' = Az - c*t1*2^d */
  polyChallenge(&cp, c);
  polyMatrixExpand(&mat, rho);

  polyVectorLNTT(&z);
  polyMatrixPointwiseMontgomery(&w1, &mat, &z);

  polyNTT(&cp);
  polyVectorKShiftLeft(&t1);
  polyVectorKNTT(&t1);
  polyVectorKPointwisePolyMontgomery(&t1, &cp, &t1);

  polyVectorKSub(&w1, &w1, &t1);
  polyVectorKReduce(&w1);
  polyVectorKInverseNTTToMont(&w1);

  /* Tái cấu trúc w1 */
  polyVectorKConditionalAddQ(&w1);
  polyVectorKUseHint(&w1, &w1, &h);
  for (int i = 0; i < DILITHIUM_K; ++i)
  {
    polyW1Pack(buf + i * DILITHIUM_POLYW1_PACKEDBYTES, &w1.vec[i]);
  }

  /* Xác thực c' == c */
  Crypto::Keccak::init(&state, DILITHIUM_STREAM256_BLOCKBYTES);
  Crypto::Keccak::absorb(&state, mu, DILITHIUM_CRHBYTES);
  Crypto::Keccak::absorb(&state, buf, DILITHIUM_K * DILITHIUM_POLYW1_PACKEDBYTES);
  Crypto::Keccak::finalize(&state, 0x1F);
  Crypto::Keccak::squeeze(c2, DILITHIUM_CTILDEBYTES, &state);

  for (int i = 0; i < DILITHIUM_CTILDEBYTES; ++i)
  {
    if (c[i] != c2[i])
    {
      return false;
    }
  }

  return true;
}

} // namespace Dilithium
