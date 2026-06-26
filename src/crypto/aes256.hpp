/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file aes256.hpp
 * @brief Khai báo thuật toán mã hóa đối xứng AES-256.
 */
#ifndef __CRYPTO_AES256_HPP
#define __CRYPTO_AES256_HPP

#include <stdint.h>

#define AES256_KEYLEN    32
#define AES256_BLOCKLEN  16
#define AES256_ROUNDS    14
#define AES256_EXPKEYLEN (AES256_BLOCKLEN * (AES256_ROUNDS + 1)) /* 240 byte */

namespace Crypto::AES256 {

/* Ngữ cảnh của AES256 */
typedef struct
{
  uint8_t roundKeys[AES256_EXPKEYLEN];
} AES256Context;

/**
 * Khởi tạo ngữ cảnh và thiết lập khóa cho AES-256
 * @param ctx con trỏ trỏ tới cấu trúc ngữ cảnh AES256Context cần khởi tạo
 * @param key mảng chứa khóa bí mật với độ dài cố định AES256_KEYLEN (32 byte / 256 bit)
 * @note Hàm này thực hiện quá trình mở rộng khóa (Key Expansion) từ 256-bit khóa ban đầu
 * thành các khóa vòng (Round Keys) để chuẩn bị cho quá trình mã hóa.
 */
void init(
    AES256Context* ctx,
    const uint8_t  key[AES256_KEYLEN]);

/**
 * Mã hóa hoặc giải mã dữ liệu sử dụng AES-256 ở chế độ CTR (Counter Mode)
 * @param ctx con trỏ trỏ tới ngữ cảnh AES-256 đã được khởi tạo khóa trước đó
 * @param iv mảng chứa giá trị khởi tạo / vectơ đếm (Initialization Vector / Nonce)
 * có độ dài bằng kích thước khối AES256_BLOCKLEN (16 byte / 128 bit)
 * @param out con trỏ trỏ tới mảng bộ đệm để chứa dữ liệu kết quả sau khi xử lý
 * @param in con trỏ trỏ tới mảng dữ liệu đầu vào cần mã hóa hoặc giải mã
 * @param len độ dài của dữ liệu đầu vào (tính bằng byte)
 */
void counter(
    const AES256Context* ctx,
    const uint8_t        iv[AES256_BLOCKLEN],
    uint8_t*             out,
    const uint8_t*       in,
    uint64_t             len);

} // namespace Crypto::AES256

#endif // __CRYPTO_AES256_HPP
