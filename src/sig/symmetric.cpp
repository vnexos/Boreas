/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file symmetric.cpp
 * @brief Triển khai giao diện SHAKE phục vụ lấy mẫu ma trận và vector ngẫu nhiên.
 */
#include "symmetric.hpp"

namespace Dilithium {

void stream128Init(Crypto::Keccak::State* state, const uint8_t seed[DILITHIUM_SEEDBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  Crypto::Keccak::init(state, DILITHIUM_STREAM128_BLOCKBYTES);
  Crypto::Keccak::absorb(state, seed, DILITHIUM_SEEDBYTES);
  Crypto::Keccak::absorb(state, t, 2);
  Crypto::Keccak::finalize(state, 0x1F); // 0x1F là domainSeparator cho SHAKE
}

void stream256Init(Crypto::Keccak::State* state, const uint8_t seed[DILITHIUM_CRHBYTES], uint16_t nonce)
{
  uint8_t t[2];
  t[0] = nonce;
  t[1] = nonce >> 8;

  Crypto::Keccak::init(state, DILITHIUM_STREAM256_BLOCKBYTES);
  Crypto::Keccak::absorb(state, seed, DILITHIUM_CRHBYTES);
  Crypto::Keccak::absorb(state, t, 2);
  Crypto::Keccak::finalize(state, 0x1F); // 0x1F là domainSeparator cho SHAKE
}

void stream128SqueezeBlocks(uint8_t* out, size_t outBlocks, Crypto::Keccak::State* state)
{
  Crypto::Keccak::squeeze(out, outBlocks * DILITHIUM_STREAM128_BLOCKBYTES, state);
}

void stream256SqueezeBlocks(uint8_t* out, size_t outBlocks, Crypto::Keccak::State* state)
{
  Crypto::Keccak::squeeze(out, outBlocks * DILITHIUM_STREAM256_BLOCKBYTES, state);
}

} // namespace Dilithium
