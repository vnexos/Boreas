/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file sha3.hpp
 * @brief Khai báo các hàm băm bảo mật họ SHA-3 (Keccak, SHAKE).
 */
#ifndef __CRYPTO_SHA_HPP
#define __CRYPTO_SHA_HPP

#include <stdint.h>

namespace Crypto {

/* Lõi của Thuật toán SHA3 */
namespace Keccak {

/* Trạng thái Keccak */
struct State
{
  uint64_t s[25]; // Trạng thái 1600-bit
  uint64_t pos;   // Vị trí hiện tại trong khối (0 đến rate)
  uint64_t rate;  // Kích thước khối (168 với SHAKE128, 136 với SHAKE256)
};

/**
 * Dịch bit vòng sang trái
 * @param x giá trị cần dịch bit
 * @param y số lượng dịch bit
 */
inline uint64_t rotL64(
    uint64_t x,
    uint64_t y);

/**
 * Hàm hoán vị lõi 24 vòng của Keccak
 * @param state trạng thái Keccak trả về sau hoán vị
 */
void f1600(
    State* state);

/**
 * Khởi tạo trạng thái
 * @param state trạng thái Keccak trả về sau khởi tạo
 * @param rate tốc độ tiêu thụ dữ liệu
 */
void init(
    State*   state,
    uint64_t rate);

/**
 * Hấp thụ dữ liệu đầu vào vào trạng thái Keccak (Giai đoạn Absorbing)
 * @param state trạng thái Keccak hiện tại (đã được khởi tạo)
 * @param in con trỏ trỏ tới mảng dữ liệu đầu vào cần băm
 * @param inlen độ dài của dữ liệu đầu vào (tính bằng byte)
 */
void absorb(
    State*         state,
    const uint8_t* in,
    uint64_t       inlen);

/**
 * Hoàn tất quá trình nạp dữ liệu và thực hiện đệm (Giai đoạn Finalize)
 * @param state trạng thái Keccak hiện tại
 * @param domainSeparator giá trị phân tách miền (dùng để phân biệt các biến thể băm như SHA3, SHAKE, cSHAKE)
 */
void finalize(
    State*  state,
    uint8_t domainSeparator);

/**
 * Trích xuất (vắt) dữ liệu băm từ trạng thái Keccak (Giai đoạn Squeezing)
 * @param out con trỏ trỏ tới mảng bộ đệm để chứa kết quả băm đầu ra
 * @param outlen độ dài kết quả băm mong muốn (tính bằng byte)
 * @param state trạng thái Keccak hiện tại (sau khi đã gọi finalize)
 */
void squeeze(
    uint8_t* out,
    uint64_t outlen,
    State*   state);

} // namespace Keccak

namespace SHA {
/**
 * Băm dữ liệu bằng thuật toán SHAKE128 (XOF - Hàm đầu ra mở rộng)
 * @param out con trỏ trỏ tới mảng bộ đệm chứa kết quả băm (độ dài tùy chọn)
 * @param outlen độ dài kết quả băm mong muốn (tính bằng byte)
 * @param in con trỏ trỏ tới mảng dữ liệu đầu vào cần băm
 * @param inlen độ dài của dữ liệu đầu vào (tính bằng byte)
 * @note SHAKE128 sử dụng rate = 1344 bits (168 byte) và domainSeparator = 0x1F.
 */
void shake128(
    uint8_t*       out,
    uint64_t       outlen,
    const uint8_t* in,
    uint64_t       inlen);

/**
 * Băm dữ liệu bằng thuật toán SHAKE256 (XOF - Hàm đầu ra mở rộng)
 * @param out con trỏ trỏ tới mảng bộ đệm chứa kết quả băm (độ dài tùy chọn)
 * @param outlen độ dài kết quả băm mong muốn (tính bằng byte)
 * @param in con trỏ trỏ tới mảng dữ liệu đầu vào cần băm
 * @param inlen độ dài của dữ liệu đầu vào (tính bằng byte)
 * @note SHAKE256 sử dụng rate = 1088 bits (136 byte) và domainSeparator = 0x1F.
 */
void shake256(
    uint8_t*       out,
    uint64_t       outlen,
    const uint8_t* in,
    uint64_t       inlen);

/**
 * Băm dữ liệu bằng thuật toán SHA3-256 (Chuẩn mã băm cố định)
 * @param h mảng bộ đệm cố định 32 byte (256 bits) để chứa kết quả băm đầu ra
 * @param in con trỏ trỏ tới mảng dữ liệu đầu vào cần băm
 * @param inlen độ dài của dữ liệu đầu vào (tính bằng byte)
 * @note SHA3-256 sử dụng rate = 1088 bits (136 byte) và domainSeparator = 0x06.
 */
void sha256(
    uint8_t        h[32],
    const uint8_t* in,
    uint64_t       inlen);

/**
 * Băm dữ liệu bằng thuật toán SHA3-512 (Chuẩn mã băm cố định)
 * @param h mảng bộ đệm cố định 64 byte (512 bits) để chứa kết quả băm đầu ra
 * @param in con trỏ trỏ tới mảng dữ liệu đầu vào cần băm
 * @param inlen độ dài của dữ liệu đầu vào (tính bằng byte)
 * @note SHA3-512 sử dụng rate = 576 bits (72 byte) và domainSeparator = 0x06.
 */
void sha512(
    uint8_t        h[64],
    const uint8_t* in,
    uint64_t       inlen);
} // namespace SHA

namespace VNExos {
/**
 * Băm dữ liệu bằng thuật toán SHAV-256 (Bản mở rộng phát triển từ Keccak)
 * @param h mảng bộ đệm cố định 32 byte (256 bits) để chứa kết quả băm đầu ra
 * @param in con trỏ trỏ tới mảng dữ liệu đầu vào cần băm
 * @param inlen độ dài của dữ liệu đầu vào (tính bằng byte)
 * @note Sử dụng cấu hình rate/capacity riêng thuộc hệ thống SHAV cho mức an toàn 256-bit.
 */
void sha256(
    uint8_t        h[32],
    const uint8_t* in,
    uint64_t       inlen);

/**
 * Băm dữ liệu bằng thuật toán SHAV-512 (Bản mở rộng phát triển từ Keccak)
 * @param h mảng bộ đệm cố định 64 byte (512 bits) để chứa kết quả băm đầu ra
 * @param in con trỏ trỏ tới mảng dữ liệu đầu vào cần băm
 * @param inlen độ dài của dữ liệu đầu vào (tính bằng byte)
 * @note Sử dụng cấu hình rate/capacity riêng thuộc hệ thống SHAV cho mức an toàn 512-bit.
 */
void sha512(
    uint8_t        h[64],
    const uint8_t* in,
    uint64_t       inlen);

/**
 * Băm dữ liệu bằng thuật toán SHAV-1024 (Bản mở rộng siêu cấp phát triển từ Keccak)
 * @param h mảng bộ đệm cố định 128 byte (1024 bits) để chứa kết quả băm đầu ra
 * @param in con trỏ trỏ tới mảng dữ liệu đầu vào cần băm
 * @param inlen độ dài của dữ liệu đầu vào (tính bằng byte)
 * @note Phiên bản mở rộng đặc biệt, cung cấp không gian trạng thái đầu ra cực lớn (128 byte).
 */
void sha1024(
    uint8_t        h[128],
    const uint8_t* in,
    uint64_t       inlen);
} // namespace VNExos

} // namespace Crypto

#endif // __CRYPTO_SHA_HPP