/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file kyber.cpp
 * @brief Triển khai giao diện mã hóa/giải mã KEM Kyber.
 */
#include "kyber.hpp"
#include "indcpa.hpp"
#include <crypto/randombytes.hpp>
#include <crypto/sha3.hpp>

namespace Kyber {

void generateKeyPair(uint8_t publicKey[KYBER_INDCCA_PUBKEYBYTES], uint8_t secretKey[KYBER_INDCCA_SECKEYBYTES])
{
  indcpaKeypair(publicKey, secretKey);

  for (int i = 0; i < KYBER_INDCPA_PUBKEYBYTES; i++)
  {
    secretKey[KYBER_INDCPA_SECKEYBYTES + i] = publicKey[i];
  }

  Crypto::SHA::sha256(secretKey + KYBER_INDCPA_SECKEYBYTES + KYBER_INDCPA_PUBKEYBYTES, publicKey, KYBER_INDCPA_PUBKEYBYTES);

  Crypto::randombytes(secretKey + KYBER_INDCPA_SECKEYBYTES + KYBER_INDCPA_PUBKEYBYTES + KYBER_SYMBYTES, KYBER_SYMBYTES);
}

void encapsulate(uint8_t ciphertext[KYBER_INDCCA_CIPHERTEXTBYTES], uint8_t sharedSecret[KYBER_SSBYTES], const uint8_t publicKey[KYBER_INDCCA_PUBKEYBYTES])
{
  uint8_t buf[2 * KYBER_SYMBYTES];
  uint8_t kr[2 * KYBER_SYMBYTES];

  Crypto::randombytes(buf, KYBER_SYMBYTES);

  Crypto::SHA::sha256(buf, buf, KYBER_SYMBYTES);
  Crypto::SHA::sha256(buf + KYBER_SYMBYTES, publicKey, KYBER_INDCPA_PUBKEYBYTES);

  Crypto::SHA::sha512(kr, buf, 2 * KYBER_SYMBYTES);

  indcpaEncrypt(ciphertext, buf, publicKey, kr + KYBER_SYMBYTES);

  Crypto::SHA::sha256(kr + KYBER_SYMBYTES, ciphertext, KYBER_INDCCA_CIPHERTEXTBYTES);
  Crypto::SHA::shake256(sharedSecret, KYBER_SSBYTES, kr, 2 * KYBER_SYMBYTES);
}

void decapsulate(uint8_t sharedSecret[KYBER_SSBYTES], const uint8_t ciphertext[KYBER_INDCCA_CIPHERTEXTBYTES], const uint8_t secretKey[KYBER_INDCCA_SECKEYBYTES])
{
  uint8_t buf[2 * KYBER_SYMBYTES];
  uint8_t kr[2 * KYBER_SYMBYTES];
  uint8_t cmp[KYBER_INDCCA_CIPHERTEXTBYTES];

  const uint8_t* pk = secretKey + KYBER_INDCPA_SECKEYBYTES;

  indcpaDecrypt(buf, ciphertext, secretKey);

  for (int i = 0; i < KYBER_SYMBYTES; i++)
  {
    buf[KYBER_SYMBYTES + i] = secretKey[KYBER_INDCPA_SECKEYBYTES + KYBER_INDCPA_PUBKEYBYTES + i];
  }

  Crypto::SHA::sha512(kr, buf, 2 * KYBER_SYMBYTES);

  indcpaEncrypt(cmp, buf, pk, kr + KYBER_SYMBYTES);

  int fail = 0;
  for (int i = 0; i < KYBER_INDCCA_CIPHERTEXTBYTES; i++)
  {
    fail |= ciphertext[i] ^ cmp[i];
  }

  fail = (fail == 0) ? 0 : 1;

  // Chọn hằng số thời gian (Constant-time selection): Nếu fail == 0, khóa chia sẻ dùng kr. Ngược lại dùng z.
  // Giá trị z nằm tại vị trí secretKey + KYBER_INDCPA_SECKEYBYTES + KYBER_INDCPA_PUBKEYBYTES + KYBER_SYMBYTES
  for (int i = 0; i < KYBER_SYMBYTES; i++)
  {
    kr[i] = (kr[i] & ~(-fail)) | (secretKey[KYBER_INDCPA_SECKEYBYTES + KYBER_INDCPA_PUBKEYBYTES + KYBER_SYMBYTES + i] & (-fail));
  }

  Crypto::SHA::sha256(kr + KYBER_SYMBYTES, ciphertext, KYBER_INDCCA_CIPHERTEXTBYTES);
  Crypto::SHA::shake256(sharedSecret, KYBER_SSBYTES, kr, 2 * KYBER_SYMBYTES);
}

} // namespace Kyber