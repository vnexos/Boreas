/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file kyber.hpp
 * @brief Khai báo cơ chế đóng gói khóa (KEM) Kyber (ML-KEM).
 */
#ifndef __KEM_KYBER_HPP
#define __KEM_KYBER_HPP

#include <stdint.h>

#define KYBER_K            4
#define KYBER_N            256                 /* Bậc của đa thức */
#define KYBER_Q            3329                /* Số Modulus dùng cho các phép toán trong trường số nguyên */
#define KYBER_Q_HALF       ((KYBER_Q + 1) / 2) /* Giá trị trung vị của Q */
#define KYBER_QINV         62209               /* Q^-1 mod 2^16 */
#define KYBER_UINT12_LIMIT 4096                /* Giới hạn của số nguyên 12 bit (2^12) */

#define KYBER_SYMBYTES 32                      /* Kích thước khóa đối xứng */
#define KYBER_SSBYTES  32                      /* Kích thước khóa chia sẻ */

/**
 * Kích thước của một đa thức sau khi được đóng gói (nén 12-bit)
 * Công thức tính:
 * - Tổng số bit cần dùng để lưu một đa thức
 *     Tổng = KYBER_N * 12 = 3072
 *   => Có tổng cộng 256 hệ số của đa thức và mỗi hệ số có kích
 *      thước 12 bit, nên để lưu trữ toàn bộ 256 hệ số thì cần
 *      3072 bit (384 byte)
 */
#define KYBER_POLYBYTES 384
/**
 * Kích thước của một mảng đa thức (1536 bytes)
 * Theo đặc tả của Kyber1024 thì ta sẽ dùng một mảng 4 đa thức
 */
#define KYBER_POLYVECBYTES (KYBER_K * KYBER_POLYBYTES)

/* Kích thước của một đa thức sau khi nén về độ phân giải: */
#define KYBER_POLYCOMPRESSEDBYTES_D5  160 /* Mức D5:  32 * d = 160 */
#define KYBER_POLYCOMPRESSEDBYTES_D11 352 /* Mức D11: 32 * d = 352 */

#define KYBER_ETA1 2                      /* Hệ số biên (Width parameter) dùng cho hàm phân phối nhị phân chuẩn (CBD) để sinh nhiễu */
#define KYBER_ETA2 2                      /* Hệ số biên (Width parameter) dùng để sinh mảng nhiễu phụ trong quá trình mã hóa/đóng gói */
#define KYBER_DU   11                     /* Số bit nén (d_u) cho mỗi hệ số của mảng đa thức trong Bản mã (Ciphertext) */
#define KYBER_DV   5                      /* Số bit nén (d_v) cho mỗi hệ số của đa thức đơn lẻ trong Bản mã (Ciphertext) */

/* Quy đổi mức nén đa thức đơn lẻ dựa trên cấu hình DV */
#define KYBER_POLYCOMPRESSEDBYTES_DV (KYBER_POLYCOMPRESSEDBYTES_D5)
/* Quy đổi mức nén đa thức đơn lẻ dựa trên cấu hình DU */
#define KYBER_POLYCOMPRESSEDBYTES_DU (KYBER_POLYCOMPRESSEDBYTES_D11)
/* Tổng kích thước của Mảng đa thức sau khi nén phục vụ cho bản mã (1408 byte) */
#define KYBER_POLYVECCOMPRESSEDBYTES_DU (KYBER_K * KYBER_POLYCOMPRESSEDBYTES_DU)

/* Kích thước tối đa của thông điệp thô trước khi mã hóa (32 byte) */
#define KYBER_INDCPA_MSGBYTES (KYBER_SYMBYTES)
/* Kích thước của khóa công khai IND-CPA thô (1568 byte) */
#define KYBER_INDCPA_PUBKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
/* Kích thước của khóa bí mật IND-CPA thô (1536 byte) */
#define KYBER_INDCPA_SECKEYBYTES (KYBER_POLYVECBYTES)
/* Kích thước tổng cộng của bản mã (Ciphertext) IND-CPA thô (1568 bytes) */
#define KYBER_INDCPA_BYTES (KYBER_POLYVECCOMPRESSEDBYTES_DU + KYBER_POLYCOMPRESSEDBYTES_DV)

/* Kích thước của khóa công khai hoàn chỉnh (1568 byte) */
#define KYBER_INDCCA_PUBKEYBYTES (KYBER_INDCPA_PUBKEYBYTES)
/**
 * Kích thước của khóa bí mật hoàn chỉnh sau khi đóng gói bảo mật (3168 byte)
 * Bao gồm 4 thành phần:
 * - KYBER_INDCPA_SECKEYBYTES (1536 byte): Mảng đa thức bí mật thô gốc (s)
 * - KYBER_INDCPA_PUBKEYBYTES (1568 byte): Gộp luôn cả khóa công khai của chính
 * mình vào bên trong phục vụ cho quá trình tái mã hóa (Re-encryption).
 * - First  KYBER_SYMBYTES (32 byte): Bản băm của khóa công khai H(PK), dùng để kiểm tra tính toàn vẹn.
 * - Second KYBER_SYMBYTES (32 byte): Giá trị từ chối ngẫu nhiên (Rejection value z), dùng để sinh khóa
 * giả đánh lừa hacker nếu bản mã bị lỗi.
 */
#define KYBER_INDCCA_SECKEYBYTES (KYBER_INDCPA_SECKEYBYTES + KYBER_INDCPA_PUBKEYBYTES + 2 * KYBER_SYMBYTES)
/* Kích thước của Bản mã hoàn chỉnh (1568 bytes) */
#define KYBER_INDCCA_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)

namespace Kyber {

/**
 * Tạo cặp khóa cho thuật toán Kyber
 * @param publicKey Khóa công khai (1568 byte)
 * @param secretKey Khóa bí mật (3168 byte)
 */
void generateKeyPair(
    uint8_t publicKey[KYBER_INDCCA_PUBKEYBYTES],
    uint8_t secretKey[KYBER_INDCCA_SECKEYBYTES]);

/**
 * Đóng gói khóa bằng thuật toán Kyber
 * @param ciphertext Mảng nhận Bản mã được đóng gói (1568 byte)
 * @param sharedSecret Mảng nhận khóa dùng chung thu được (32 byte)
 * @param publicKey Mảng chứa khóa công khai của người nhận (1568 byte)
 */
void encapsulate(
    uint8_t       ciphertext[KYBER_INDCCA_CIPHERTEXTBYTES],
    uint8_t       sharedSecret[KYBER_SSBYTES],
    const uint8_t publicKey[KYBER_INDCCA_PUBKEYBYTES]);

/**
 * Mở gói khóa bằng thuật toán Kyber
 * @param sharedSecret Mảng nhận khóa dùng chung khôi phục được (32 byte)
 * @param ciphertext Mảng chứa Bảng mã nhận được (1568 byte)
 * @param secretKey Mảng chứa khóa bí mật hoàn chỉnh của người nhận (3168 byte)
 */
void decapsulate(
    uint8_t       sharedSecret[KYBER_SSBYTES],
    const uint8_t ciphertext[KYBER_INDCCA_CIPHERTEXTBYTES],
    const uint8_t secretKey[KYBER_INDCCA_SECKEYBYTES]);

} // namespace Kyber

#endif // __KEM_KYBER_HPP
