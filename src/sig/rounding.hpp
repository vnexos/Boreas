/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file rounding.hpp
 * @brief Khai báo các phép toán làm tròn và tạo hint bảo mật.
 */
#ifndef __SIG_ROUNDING_HPP
#define __SIG_ROUNDING_HPP

#include <stdint.h>

namespace Dilithium {

/**
 * Tính toán thành phần phần cứng cho làm tròn (power2round)
 * Đối với phần tử trường hữu hạn a, tính a0, a1 sao cho
 * a mod^+ Q = a1*2^D + a0 với -2^{D-1} < a0 <= 2^{D-1}.
 * Giả định a là giá trị đại diện chuẩn.
 *
 * @param a0 con trỏ tới thành phần bit thấp đầu ra
 * @param a phần tử đầu vào
 * @return phần tử bit cao a1
 */
int32_t power2round(int32_t* a0, int32_t a);

/**
 * Phân rã phần tử (decompose)
 * Đối với phần tử trường hữu hạn a, tính các bit cao và thấp a0, a1 sao cho
 * a mod^+ Q = a1*ALPHA + a0.
 *
 * @param a0 con trỏ tới thành phần bit thấp đầu ra
 * @param a phần tử đầu vào
 * @return phần tử bit cao a1
 */
int32_t decompose(int32_t* a0, int32_t a);

/**
 * Tạo Hint (makeHint)
 * Tính toán bit hint (gợi ý) chỉ ra xem các bit thấp của đầu vào
 * có bị tràn sang các bit cao hay không.
 *
 * @param a0 phần bit thấp
 * @param a1 phần bit cao
 * @return 1 nếu có tràn, 0 nếu không
 */
unsigned int makeHint(int32_t a0, int32_t a1);

/**
 * Sử dụng Hint (useHint)
 * Chỉnh sửa lại các bit cao dựa trên bit hint.
 *
 * @param a phần tử đầu vào
 * @param hint bit gợi ý
 * @return các bit cao sau khi được chỉnh sửa
 */
int32_t useHint(int32_t a, unsigned int hint);

} // namespace Dilithium

#endif // __SIG_ROUNDING_HPP
