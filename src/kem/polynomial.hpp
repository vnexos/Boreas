/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file polynomial.hpp
 * @brief Khai báo cấu trúc và phép toán đa thức cho Kyber.
 */
#ifndef __KEM_POLY_HPP
#define __KEM_POLY_HPP

#include "kyber.hpp"

namespace Kyber {

typedef struct alignas(32)
{
  int16_t coefficients[KYBER_N]; // Các hệ số của đa thức (sửa thành int16_t để phù hợp với các phép tính)
} Polynomial;

typedef struct alignas(32)
{
  Polynomial polynomials[KYBER_K]; // Các đa thức trong mảng
} PolynomialVector;

typedef struct alignas(32)
{
  PolynomialVector vectors[KYBER_K]; // Các mảng trong ma trận
} PolynomialMatrix;

void polyAdd(Polynomial* r, const Polynomial* a, const Polynomial* b);
void polySub(Polynomial* r, const Polynomial* a, const Polynomial* b);
void polyNTT(Polynomial* r);
void polyInvNTT(Polynomial* r);
void polyPointwiseMontgomery(Polynomial* r, const Polynomial* a, const Polynomial* b);
void polyReduce(Polynomial* r);
void polyCondSubQ(Polynomial* r);
void polyToMont(Polynomial* r);

void polyVectorAdd(PolynomialVector* r, const PolynomialVector* a, const PolynomialVector* b);
void polyVectorNTT(PolynomialVector* r);
void polyVectorInvNTT(PolynomialVector* r);
void polyVectorPointwiseMontgomery(PolynomialVector* r, const PolynomialVector* a, const PolynomialVector* b);
void polyVectorReduce(PolynomialVector* r);
void polyVectorCondSubQ(PolynomialVector* r);

// Parse từ mảng byte thành đa thức
void polyFromBytes(Polynomial* r, const uint8_t a[KYBER_POLYBYTES]);
void polyToBytes(uint8_t r[KYBER_POLYBYTES], const Polynomial* a);

void polyFromMsg(Polynomial* r, const uint8_t msg[KYBER_INDCPA_MSGBYTES]);
void polyToMsg(uint8_t msg[KYBER_INDCPA_MSGBYTES], const Polynomial* a);

void polyCompress(uint8_t r[KYBER_POLYCOMPRESSEDBYTES_DU], const Polynomial* a);
void polyDecompress(Polynomial* r, const uint8_t a[KYBER_POLYCOMPRESSEDBYTES_DU]);

void polyVectorCompress(uint8_t r[KYBER_POLYVECCOMPRESSEDBYTES_DU], const PolynomialVector* a);
void polyVectorDecompress(PolynomialVector* r, const uint8_t a[KYBER_POLYVECCOMPRESSEDBYTES_DU]);

// Lấy mẫu
void polyUniform(Polynomial* r, const uint8_t seed[KYBER_SYMBYTES], uint8_t nonce1, uint8_t nonce2);
void polyCBD(Polynomial* r, const uint8_t buf[KYBER_ETA1 * KYBER_N / 4]);

void generateMatrixA(PolynomialMatrix* matrixA, const uint8_t seed[KYBER_SYMBYTES], bool transposed);

} // namespace Kyber

#endif // __KEM_POLY_HPP