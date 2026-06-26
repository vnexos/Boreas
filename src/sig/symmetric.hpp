/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file symmetric.hpp
 * @brief Khai báo các hàm Keccak XOF chuyên biệt cho sinh mẫu đa thức.
 */
#ifndef __SIG_SYMMETRIC_HPP
#define __SIG_SYMMETRIC_HPP

#include "dilithium.hpp"
#include <crypto/sha3.hpp>
#include <stddef.h>
#include <stdint.h>

namespace Dilithium {

/* Định nghĩa kích thước khối cho SHAKE128 và SHAKE256 */
#define DILITHIUM_STREAM128_BLOCKBYTES 168
#define DILITHIUM_STREAM256_BLOCKBYTES 136

/**
 * Khởi tạo luồng SHAKE128
 * Sử dụng để mở rộng ma trận A.
 *
 * @param state trạng thái Keccak
 * @param seed mảng seed đầu vào
 * @param nonce giá trị nonce (thường là chỉ số của ma trận)
 */
void stream128Init(Crypto::Keccak::State* state, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce);

/**
 * Khởi tạo luồng SHAKE256
 * Sử dụng để lấy mẫu các đa thức bí mật.
 *
 * @param state trạng thái Keccak
 * @param seed mảng seed đầu vào
 * @param nonce giá trị nonce
 */
void stream256Init(Crypto::Keccak::State* state, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce);

/**
 * Trích xuất các khối dữ liệu từ luồng SHAKE128
 *
 * @param out mảng đầu ra
 * @param outBlocks số lượng khối cần trích xuất
 * @param state trạng thái Keccak hiện tại
 */
void stream128SqueezeBlocks(uint8_t* out, size_t outBlocks, Crypto::Keccak::State* state);

/**
 * Trích xuất các khối dữ liệu từ luồng SHAKE256
 *
 * @param out mảng đầu ra
 * @param outBlocks số lượng khối cần trích xuất
 * @param state trạng thái Keccak hiện tại
 */
void stream256SqueezeBlocks(uint8_t* out, size_t outBlocks, Crypto::Keccak::State* state);

} // namespace Dilithium

#endif // __SIG_SYMMETRIC_HPP
