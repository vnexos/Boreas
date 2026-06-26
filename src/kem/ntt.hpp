/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file ntt.hpp
 * @brief Khai báo phép biến đổi Number Theoretic Transform (NTT) cho Kyber.
 */
#ifndef __KEM_NTT_HPP
#define __KEM_NTT_HPP

#include <stdint.h>

namespace Kyber {

/**
 * @brief Khởi tạo các hệ số Zetas cho NTT
 * Cần được gọi trước khi sử dụng NTT lần đầu tiên.
 */
void initZetas();

/**
 * @brief Number Theoretic Transform (NTT)
 * Biến đổi một đa thức 256 hệ số sang miền NTT
 */
void applyNTT(int16_t r[256]);

/**
 * @brief Inverse Number Theoretic Transform (INTT)
 * Biến đổi ngược từ miền NTT về miền đa thức ban đầu
 */
void applyInverseNTT(int16_t r[256]);

/**
 * @brief Nhân hai đa thức từng điểm trong miền NTT (Point-wise Multiplication)
 */
void pointwiseMontgomery(int16_t r[256], const int16_t a[256], const int16_t b[256]);

} // namespace Kyber

#endif // __KEM_NTT_HPP
