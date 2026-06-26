/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file indcpa.hpp
 * @brief Khai báo thuật toán mã hóa công khai IND-CPA của thuật toán Kyber.
 */
#ifndef __KEM_INDCPA_HPP
#define __KEM_INDCPA_HPP

#include "kyber.hpp"

namespace Kyber {

void indcpaKeypair(uint8_t pk[KYBER_INDCPA_PUBKEYBYTES], uint8_t sk[KYBER_INDCPA_SECKEYBYTES]);
void indcpaEncrypt(uint8_t c[KYBER_INDCPA_BYTES], const uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t pk[KYBER_INDCPA_PUBKEYBYTES], const uint8_t coins[KYBER_SYMBYTES]);
void indcpaDecrypt(uint8_t m[KYBER_INDCPA_MSGBYTES], const uint8_t c[KYBER_INDCPA_BYTES], const uint8_t sk[KYBER_INDCPA_SECKEYBYTES]);

} // namespace Kyber

#endif // __KEM_INDCPA_HPP
