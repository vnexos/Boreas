/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file dilithium.hpp
 * @brief Khai báo thuật toán chữ ký số Dilithium (ML-DSA-87).
 */
#ifndef __SIG_DILITHIUM_HPP
#define __SIG_DILITHIUM_HPP

#include <stddef.h>
#include <stdint.h>

/* Thông số cho Dilithium (Cấu hình Mode 5 - Security Level 5 tương đương AES-256) */
#define DILITHIUM_K      8
#define DILITHIUM_L      7
#define DILITHIUM_ETA    2
#define DILITHIUM_TAU    60
#define DILITHIUM_BETA   120
#define DILITHIUM_GAMMA1 (1 << 19)
#define DILITHIUM_GAMMA2 ((DILITHIUM_Q - 1) / 32)
#define DILITHIUM_OMEGA  75

#define DILITHIUM_N             256     /* Bậc của đa thức */
#define DILITHIUM_Q             8380417 /* Số Modulus */
#define DILITHIUM_D             13      /* Số bit bị cắt bỏ */
#define DILITHIUM_ROOT_OF_UNITY 1753

#define DILITHIUM_SEEDBYTES   32 /* Kích thước seed */
#define DILITHIUM_CRHBYTES    64 /* Kích thước hash chống va chạm */
#define DILITHIUM_TRBYTES     64 /* Kích thước hash dùng cho chữ ký */
#define DILITHIUM_RNDBYTES    32 /* Kích thước số ngẫu nhiên */
#define DILITHIUM_CTILDEBYTES 64 /* Kích thước của hash C tilde (Mode 5) */

/* Kích thước của khóa và chữ ký theo cấu hình Mode 5 */
#define DILITHIUM_PUBLICKEYBYTES 2592 /* Kích thước khóa công khai */
#define DILITHIUM_SECRETKEYBYTES 4896 /* Kích thước khóa bí mật */
#define DILITHIUM_BYTES          4627 /* Kích thước chữ ký tối đa */

namespace Dilithium {

/**
 * Tạo cặp khóa cho thuật toán chữ ký số Dilithium
 * @param publicKey Khóa công khai
 * @param secretKey Khóa bí mật
 */
void generateKeyPair(
    uint8_t publicKey[DILITHIUM_PUBLICKEYBYTES],
    uint8_t secretKey[DILITHIUM_SECRETKEYBYTES]);

/**
 * Tạo chữ ký cho thông điệp bằng khóa bí mật
 * @param signature Mảng nhận chữ ký sinh ra
 * @param signatureLength Độ dài thực tế của chữ ký
 * @param message Thông điệp cần ký
 * @param messageLength Chiều dài thông điệp
 * @param secretKey Khóa bí mật của người ký
 */
void sign(
    uint8_t        signature[DILITHIUM_BYTES],
    size_t*        signatureLength,
    const uint8_t* message,
    size_t         messageLength,
    const uint8_t  secretKey[DILITHIUM_SECRETKEYBYTES]);

/**
 * Xác thực chữ ký của thông điệp bằng khóa công khai
 * @param signature Mảng chứa chữ ký cần xác thực
 * @param signatureLength Độ dài của chữ ký
 * @param message Thông điệp đã được ký
 * @param messageLength Chiều dài thông điệp
 * @param publicKey Khóa công khai của người ký
 * @return true nếu chữ ký hợp lệ, false nếu không hợp lệ
 */
bool verify(
    const uint8_t  signature[DILITHIUM_BYTES],
    size_t         signatureLength,
    const uint8_t* message,
    size_t         messageLength,
    const uint8_t  publicKey[DILITHIUM_PUBLICKEYBYTES]);

} // namespace Dilithium

#endif // __SIG_DILITHIUM_HPP
