/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file reduce.hpp
 * @brief Khai báo các phép toán rút gọn module trên trường hữu hạn của Dilithium.
 */
#ifndef __SIG_REDUCE_HPP
#define __SIG_REDUCE_HPP

#include <stdint.h>

namespace Dilithium {

/* 2^32 % Q */
#define DILITHIUM_MONT -4186625
/* Q^-1 mod 2^32 */
#define DILITHIUM_QINV 58728449

/**
 * Phép rút gọn Montgomery
 * Đối với phần tử trường hữu hạn a thỏa mãn -2^{31}Q <= a <= Q*2^31,
 * tính r \equiv a*2^{-32} (mod Q) sao cho -Q < r < Q.
 *
 * @param a phần tử trường hữu hạn
 * @return giá trị r đã được rút gọn
 */
int32_t montgomeryReduce(int64_t a);

/**
 * Phép rút gọn 32-bit (reduce32)
 * Đối với phần tử trường hữu hạn a thỏa mãn a <= 2^{31} - 2^{22} - 1,
 * tính r \equiv a (mod Q) sao cho -6283008 <= r <= 6283008.
 *
 * @param a phần tử trường hữu hạn
 * @return giá trị r đã được rút gọn
 */
int32_t reduce32(int32_t a);

/**
 * Cộng thêm Modulus Q có điều kiện (conditionalAddQ)
 * Cộng thêm Modulus Q nếu hệ số đầu vào là số âm.
 *
 * @param a phần tử trường hữu hạn
 * @return giá trị r
 */
int32_t conditionalAddQ(int32_t a);

/**
 * Cố định giá trị (freeze)
 * Đối với phần tử trường hữu hạn a, tính giá trị đại diện chuẩn
 * r = a mod^+ Q (sao cho r nằm trong khoảng từ 0 đến Q-1).
 *
 * @param a phần tử trường hữu hạn
 * @return giá trị chuẩn hóa r
 */
int32_t freeze(int32_t a);

} // namespace Dilithium

#endif // __SIG_REDUCE_HPP
