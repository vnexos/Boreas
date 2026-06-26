/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file randombytes.hpp
 * @brief Khai báo hàm sinh số ngẫu nhiên an toàn mật mã (CSPRNG).
 */
#ifndef __CRYPTO_RANDOMBYTES_HPP
#define __CRYPTO_RANDOMBYTES_HPP

#include <stdint.h>

namespace Crypto {

/**
 * @brief Cung cấp Ngẫu Tố (hạt giống) ban đầu cho bộ sinh số ngẫu nhiên CSPRNG.
 * Hàm này có thể được gọi nhiều lần. Mỗi lần gọi, dữ liệu sẽ được hấp thụ (absorb)
 * vào trạng thái nội bộ của CSPRNG kết hợp với Ngẫu Tố cũ (để không làm mất tính ngẫu nhiên trước đó).
 *
 * @param seed Con trỏ trỏ tới mảng dữ liệu ngẫu nhiên thô (Ngẫu tố phần cứng).
 * @param len Độ dài của dữ liệu Ngẫu tố.
 */
void randombytes_stir(const uint8_t* seed, uint64_t len);

/**
 * @brief Sinh chuỗi số giả ngẫu nhiên an toàn (CSPRNG).
 * Hàm này có thể được sử dụng ở mọi nơi để lấy một chuỗi byte ngẫu nhiên.
 * Nếu `randombytes_stir` chưa từng được gọi, hàm sẽ tự động khởi tạo với seed rỗng
 * (không khuyến cáo dùng cho môi trường thật, cần nạp phần cứng trước).
 *
 * @param buf Con trỏ trỏ tới mảng bộ đệm để chứa dữ liệu ngẫu nhiên.
 * @param len Độ dài chuỗi dữ liệu ngẫu nhiên cần sinh.
 */
void randombytes(uint8_t* buf, uint64_t len);

} // namespace Crypto

#endif // __CRYPTO_RANDOMBYTES_HPP
