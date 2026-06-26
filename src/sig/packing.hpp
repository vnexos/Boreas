/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file packing.hpp
 * @brief Khai báo các hàm đóng gói/mở gói cấu trúc dữ liệu khóa và chữ ký.
 */
#ifndef __SIG_PACKING_HPP
#define __SIG_PACKING_HPP

#include "dilithium.hpp"
#include "polynomial.hpp"
#include <stdint.h>

namespace Dilithium {

/* Định nghĩa kích thước đóng gói cho từng đa thức trong ML-DSA-87 */
#define DILITHIUM_POLYETA_PACKEDBYTES  96
#define DILITHIUM_POLYT1_PACKEDBYTES   320
#define DILITHIUM_POLYT0_PACKEDBYTES   416
#define DILITHIUM_POLYZ_PACKEDBYTES    640
#define DILITHIUM_POLYW1_PACKEDBYTES   128
#define DILITHIUM_POLYVECH_PACKEDBYTES (DILITHIUM_OMEGA + DILITHIUM_K)

/* Các hàm đóng gói và mở gói Đa thức đơn lẻ */
void polyEtaPack(uint8_t* r, const Polynomial* a);
void polyEtaUnpack(Polynomial* r, const uint8_t* a);
void polyT1Pack(uint8_t* r, const Polynomial* a);
void polyT1Unpack(Polynomial* r, const uint8_t* a);
void polyT0Pack(uint8_t* r, const Polynomial* a);
void polyT0Unpack(Polynomial* r, const uint8_t* a);
void polyZPack(uint8_t* r, const Polynomial* a);
void polyZUnpack(Polynomial* r, const uint8_t* a);
void polyW1Pack(uint8_t* r, const Polynomial* a);

/* Các hàm đóng gói Khóa Công Khai (Public Key) */
void packPublicKey(uint8_t pk[DILITHIUM_PUBLICKEYBYTES], const uint8_t rho[DILITHIUM_SEEDBYTES], const PolynomialVectorK* t1);
void unpackPublicKey(uint8_t rho[DILITHIUM_SEEDBYTES], PolynomialVectorK* t1, const uint8_t pk[DILITHIUM_PUBLICKEYBYTES]);

/* Các hàm đóng gói Khóa Bí Mật (Secret Key) */
void packSecretKey(uint8_t sk[DILITHIUM_SECRETKEYBYTES], const uint8_t rho[DILITHIUM_SEEDBYTES], const uint8_t tr[DILITHIUM_TRBYTES], const uint8_t key[DILITHIUM_SEEDBYTES], const PolynomialVectorK* t0, const PolynomialVectorL* s1, const PolynomialVectorK* s2);
void unpackSecretKey(uint8_t rho[DILITHIUM_SEEDBYTES], uint8_t tr[DILITHIUM_TRBYTES], uint8_t key[DILITHIUM_SEEDBYTES], PolynomialVectorK* t0, PolynomialVectorL* s1, PolynomialVectorK* s2, const uint8_t sk[DILITHIUM_SECRETKEYBYTES]);

/* Các hàm đóng gói Chữ Ký (Signature) */
void packSignature(uint8_t sig[DILITHIUM_BYTES], const uint8_t c[DILITHIUM_CTILDEBYTES], const PolynomialVectorL* z, const PolynomialVectorK* h);
int  unpackSignature(uint8_t c[DILITHIUM_CTILDEBYTES], PolynomialVectorL* z, PolynomialVectorK* h, const uint8_t sig[DILITHIUM_BYTES]);

} // namespace Dilithium

#endif // __SIG_PACKING_HPP
