/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file polynomial.hpp
 * @brief Khai báo cấu trúc và phép toán đa thức của Dilithium.
 */
#ifndef __SIG_POLYNOMIAL_HPP
#define __SIG_POLYNOMIAL_HPP

#include "dilithium.hpp"
#include <stdint.h>

namespace Dilithium {

/* Cấu trúc Đa thức với N hệ số */
typedef struct alignas(32)
{
  int32_t coeffs[DILITHIUM_N];
} Polynomial;

/* Vector Đa thức có kích thước L */
typedef struct alignas(32)
{
  Polynomial vec[DILITHIUM_L];
} PolynomialVectorL;

/* Vector Đa thức có kích thước K */
typedef struct alignas(32)
{
  Polynomial vec[DILITHIUM_K];
} PolynomialVectorK;

/* Ma trận Đa thức kích thước K x L */
typedef struct alignas(32)
{
  PolynomialVectorL mat[DILITHIUM_K];
} PolynomialMatrix;

/* Các phép toán cơ bản trên Đa thức */
void         polyReduce(Polynomial* a);
void         polyConditionalAddQ(Polynomial* a);
void         polyAdd(Polynomial* c, const Polynomial* a, const Polynomial* b);
void         polySub(Polynomial* c, const Polynomial* a, const Polynomial* b);
void         polyShiftLeft(Polynomial* a);
void         polyNTT(Polynomial* a);
void         polyInverseNTTToMont(Polynomial* a);
void         polyPointwiseMontgomery(Polynomial* c, const Polynomial* a, const Polynomial* b);
void         polyPower2Round(Polynomial* a1, Polynomial* a0, const Polynomial* a);
void         polyDecompose(Polynomial* a1, Polynomial* a0, const Polynomial* a);
unsigned int polyMakeHint(Polynomial* h, const Polynomial* a0, const Polynomial* a1);
void         polyUseHint(Polynomial* b, const Polynomial* a, const Polynomial* h);
int          polyCheckNorm(const Polynomial* a, int32_t bound);

/* Lấy mẫu đa thức */
void polyUniform(Polynomial* a, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce);
void polyUniformEta(Polynomial* a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void polyUniformGamma1(Polynomial* a, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void polyChallenge(Polynomial* c, const uint8_t seed[DILITHIUM_CTILDEBYTES]);

/* Các phép toán trên Vector Đa thức kích thước L */
void polyVectorLUniformEta(PolynomialVectorL* v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void polyVectorLUniformGamma1(PolynomialVectorL* v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void polyVectorLReduce(PolynomialVectorL* v);
void polyVectorLAdd(PolynomialVectorL* w, const PolynomialVectorL* u, const PolynomialVectorL* v);
void polyVectorLNTT(PolynomialVectorL* v);
void polyVectorLInverseNTTToMont(PolynomialVectorL* v);
void polyVectorLPointwisePolyMontgomery(PolynomialVectorL* r, const Polynomial* a, const PolynomialVectorL* v);
void polyVectorLPointwiseAccMontgomery(Polynomial* w, const PolynomialVectorL* u, const PolynomialVectorL* v);
int  polyVectorLCheckNorm(const PolynomialVectorL* v, int32_t bound);

/* Các phép toán trên Vector Đa thức kích thước K */
void         polyVectorKUniformEta(PolynomialVectorK* v, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);
void         polyVectorKReduce(PolynomialVectorK* v);
void         polyVectorKConditionalAddQ(PolynomialVectorK* v);
void         polyVectorKAdd(PolynomialVectorK* w, const PolynomialVectorK* u, const PolynomialVectorK* v);
void         polyVectorKSub(PolynomialVectorK* w, const PolynomialVectorK* u, const PolynomialVectorK* v);
void         polyVectorKShiftLeft(PolynomialVectorK* v);
void         polyVectorKNTT(PolynomialVectorK* v);
void         polyVectorKInverseNTTToMont(PolynomialVectorK* v);
void         polyVectorKPointwisePolyMontgomery(PolynomialVectorK* r, const Polynomial* a, const PolynomialVectorK* v);
int          polyVectorKCheckNorm(const PolynomialVectorK* v, int32_t bound);
void         polyVectorKPower2Round(PolynomialVectorK* v1, PolynomialVectorK* v0, const PolynomialVectorK* v);
void         polyVectorKDecompose(PolynomialVectorK* v1, PolynomialVectorK* v0, const PolynomialVectorK* v);
unsigned int polyVectorKMakeHint(PolynomialVectorK* h, const PolynomialVectorK* v0, const PolynomialVectorK* v1);
void         polyVectorKUseHint(PolynomialVectorK* w, const PolynomialVectorK* v, const PolynomialVectorK* h);

/* Các phép toán trên Ma trận Đa thức */
void polyMatrixExpand(PolynomialMatrix* mat, const uint8_t rho[DILITHIUM_SEEDBYTES]);
void polyMatrixPointwiseMontgomery(PolynomialVectorK* t, const PolynomialMatrix* mat, const PolynomialVectorL* v);

} // namespace Dilithium

#endif // __SIG_POLYNOMIAL_HPP
