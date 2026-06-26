/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file ntt.hpp
 * @brief Khai báo phép biến đổi Number Theoretic Transform (NTT) đặc thù của Dilithium.
 */
#ifndef __SIG_NTT_HPP
#define __SIG_NTT_HPP

#include "dilithium.hpp"
#include <stdint.h>

namespace Dilithium {

/**
 * Biến đổi NTT (Number Theoretic Transform)
 * Áp dụng biến đổi NTT trên trường Modulus Q của Dilithium.
 * Thực hiện in-place (trực tiếp trên mảng).
 *
 * @param a Mảng hệ số đa thức đầu vào/ra (độ dài N)
 */
void applyNTT(int32_t a[DILITHIUM_N]);

/**
 * Biến đổi ngược NTT (Inverse NTT)
 * Biến đổi ngược NTT và nhân với hằng số Montgomery 2^32.
 * Thực hiện in-place (trực tiếp trên mảng).
 *
 * @param a Mảng hệ số đa thức đầu vào/ra (độ dài N)
 */
void applyInverseNTT(int32_t a[DILITHIUM_N]);

} // namespace Dilithium

#endif // __SIG_NTT_HPP
