/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file randombytes.cpp
 * @brief Triển khai hàm sinh số ngẫu nhiên an toàn mật mã.
 */
#include "randombytes.hpp"
#include "sha3.hpp"

namespace Crypto {

static Keccak::State prng_state;
static bool          prng_initialized = false;

void randombytes_stir(const uint8_t* seed, uint64_t len)
{
  if (prng_initialized)
  {
    // Lưu lại Ngẫu Tố (entropy) 32 byte (256-bit) hiện tại của state cũ để không làm mất ngẫu nhiên
    uint8_t old_entropy[32];
    Keccak::squeeze(old_entropy, 32, &prng_state);

    // Khởi tạo lại trạng thái mới
    Keccak::init(&prng_state, 136); // Rate 136 = SHAKE256

    // Hấp thụ Ngẫu Tố (entropy) cũ
    Keccak::absorb(&prng_state, old_entropy, 32);

    // Hấp thụ seed mới (nếu có)
    if (seed != nullptr && len > 0)
    {
      Keccak::absorb(&prng_state, seed, len);
    }

    // Đóng băng quá trình absorb và đưa vào trạng thái squeeze
    Keccak::finalize(&prng_state, 0x1F); // SHAKE domain separator
  } else
  {
    Keccak::init(&prng_state, 136); // Rate 136 = SHAKE256

    if (seed != nullptr && len > 0)
    {
      Keccak::absorb(&prng_state, seed, len);
    }

    Keccak::finalize(&prng_state, 0x1F); // SHAKE domain separator
    prng_initialized = true;
  }
}

void randombytes(uint8_t* buf, uint64_t len)
{
  // Tự động khởi tạo nếu chưa từng được stir (rất hữu ích lúc test)
  if (!prng_initialized)
  {
    randombytes_stir(nullptr, 0);
  }

  // Dùng hàm squeeze để vắt byte ngẫu nhiên vô hạn (SHAKE256 / XOF)
  Keccak::squeeze(buf, len, &prng_state);
}

} // namespace Crypto