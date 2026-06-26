/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file reduce.hpp
 * @brief Khai báo các phép toán rút gọn module trên trường hữu hạn cho Kyber.
 */
#ifndef __KEM_REDUCE_HPP
#define __KEM_REDUCE_HPP

#include <stdint.h>

namespace Kyber {

/**
 * @brief Rút gọn Montgomery
 * Tính a * 2^{-16} mod q
 */
int16_t montgomeryReduce(int32_t a);

/**
 * @brief Rút gọn Barrett
 * Tính a mod q
 */
int16_t barrettReduce(int16_t a);

/**
 * @brief Cộng có điều kiện (Conditional Add Q)
 * Tính a + q nếu a < 0
 */
int16_t caddQ(int16_t a);

} // namespace Kyber

#endif // __KEM_REDUCE_HPP
