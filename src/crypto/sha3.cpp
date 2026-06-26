/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file sha3.cpp
 * @brief Triển khai các hàm băm và XOF (Extendable-Output Functions) họ SHA-3.
 */
#include "sha3.hpp"

// Bảng hằng số vòng (Round Constants)
const uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008};

// Bảng hằng số dịch bit vòng (Rotation Constants)
const uint64_t ROTC[5][5] = {
    {0, 36, 3, 41, 18},
    {1, 44, 10, 45, 2},
    {62, 6, 43, 15, 61},
    {28, 55, 25, 21, 56},
    {27, 20, 39, 8, 14}};

inline uint64_t Crypto::Keccak::rotL64(uint64_t x, uint64_t y)
{
  uint64_t shift = y % 64;
  if (!shift)
    return x;
  return (x << shift) | (x >> (64 - shift));
}

void Crypto::Keccak::f1600(Crypto::Keccak::State* state)
{
  uint64_t C[5], D[5];
  uint64_t B[25];

  for (uint64_t round = 0; round < 24; round++)
  {
    // Bước biến đổi Theta
    for (uint64_t x = 0; x < 5; x++)
    {
      C[x] = state->s[x + 5 * 0] ^ state->s[x + 5 * 1] ^ state->s[x + 5 * 2] ^ state->s[x + 5 * 3] ^ state->s[x + 5 * 4];
    }
    for (uint64_t x = 0; x < 5; x++)
    {
      D[x] = C[(x + 4) % 5] ^ rotL64(C[(x + 1) % 5], 1);
    }
    for (uint64_t y = 0; y < 5; y++)
    {
      for (uint64_t x = 0; x < 5; x++)
      {
        state->s[x + 5 * y] ^= D[x];
      }
    }

    // Bước biến đổi Rho và Pi
    for (uint64_t x = 0; x < 5; x++)
    {
      for (uint64_t y = 0; y < 5; y++)
      {
        B[y + 5 * ((2 * x + 3 * y) % 5)] = rotL64(state->s[x + 5 * y], ROTC[x][y]);
      }
    }

    // Bước biến đổi Chi
    for (uint64_t y = 0; y < 5; y++)
    {
      for (uint64_t x = 0; x < 5; x++)
      {
        state->s[x + 5 * y] = B[x + 5 * y] ^ ((~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y]);
      }
    }

    // Bước biến đổi Iota
    state->s[0] ^= RC[round];
  }
}

void Crypto::Keccak::init(Crypto::Keccak::State* state, uint64_t rate)
{
  for (uint8_t i = 0; i < 25; i++)
    state->s[i] = 0;
  state->pos  = 0;
  state->rate = rate;
}

void Crypto::Keccak::absorb(Crypto::Keccak::State* state, const uint8_t* in, uint64_t inlen)
{
  // Ép kiểu mảng 64-bit thành mảng 8-bit để ghi từng byte
  uint8_t* state_bytes = (uint8_t*)state->s;

  while (inlen > 0)
  {
    uint64_t chunk = state->rate - state->pos;
    if (chunk > inlen) chunk = inlen;

    // Phép toán XOR dữ liệu mới vào trạng thái hiện tại
    for (uint64_t i = 0; i < chunk; i++)
    {
      state_bytes[state->pos + i] ^= in[i];
    }

    state->pos += chunk;
    in         += chunk;
    inlen      -= chunk;

    if (state->pos == state->rate)
    {
      f1600(state);
      state->pos = 0;
    }
  }
}

void Crypto::Keccak::finalize(Crypto::Keccak::State* state, uint8_t domainSeparator)
{
  uint8_t* state_bytes = (uint8_t*)state->s;

  // Thêm byte phân tách miền (ví dụ: 0x1F cho SHAKE, 0x06 cho SHA-3)
  state_bytes[state->pos] ^= domainSeparator;

  // Thêm bit 1 vào vị trí cuối cùng của khối (chuẩn đệm đa bit của Keccak)
  state_bytes[state->rate - 1] ^= 0x80;

  // Chạy hoán vị lần cuối
  f1600(state);

  // Reset vị trí để chuẩn bị cho quá trình vắt dữ liệu
  state->pos = 0;
}

void Crypto::Keccak::squeeze(uint8_t* out, uint64_t outlen, Crypto::Keccak::State* state)
{
  uint8_t* state_bytes = (uint8_t*)state->s;

  while (outlen > 0)
  {
    // Nếu đã vắt cạn khối hiện tại, chạy hoán vị để sinh khối ngẫu nhiên mới
    if (state->pos == state->rate)
    {
      f1600(state);
      state->pos = 0;
    }

    uint64_t chunk = state->rate - state->pos;
    if (chunk > outlen) chunk = outlen;

    // Trích xuất dữ liệu
    for (uint64_t i = 0; i < chunk; i++)
    {
      out[i] = state_bytes[state->pos + i];
    }

    state->pos += chunk;
    out        += chunk;
    outlen     -= chunk;
  }
}

void Crypto::SHA::shake128(uint8_t* out, uint64_t outlen, const uint8_t* in, uint64_t inlen)
{
  Crypto::Keccak::State state;
  init(&state, 168);      // SHAKE128 có tỷ lệ = 168 byte (1344 bit)
  absorb(&state, in, inlen);
  finalize(&state, 0x1F); // Byte phân tách miền chuẩn của SHAKE là 0x1F
  squeeze(out, outlen, &state);
}

void Crypto::SHA::shake256(uint8_t* out, uint64_t outlen, const uint8_t* in, uint64_t inlen)
{
  Crypto::Keccak::State state;
  init(&state, 136);      // SHAKE256 có tỷ lệ = 136 byte (1088 bit)
  absorb(&state, in, inlen);
  finalize(&state, 0x1F); // Byte phân tách miền chuẩn của SHAKE là 0x1F
  squeeze(out, outlen, &state);
}

void Crypto::SHA::sha256(uint8_t h[32], const uint8_t* in, uint64_t inlen)
{
  Crypto::Keccak::State state;
  init(&state, 136);      // SHA3-256 có tỷ lệ = 136 byte (1088 bit)
  absorb(&state, in, inlen);
  finalize(&state, 0x06); // Byte phân tách miền chuẩn của SHA-3 là 0x06
  squeeze(h, 32, &state); // Chỉ vắt đúng 32 byte
}

void Crypto::SHA::sha512(uint8_t h[64], const uint8_t* in, uint64_t inlen)
{
  Crypto::Keccak::State state;
  init(&state, 72);       // SHA3-512 có tỷ lệ = 72 byte (576 bit)
  absorb(&state, in, inlen);
  finalize(&state, 0x06); // Byte phân tách miền chuẩn của SHA-3 là 0x06
  squeeze(h, 64, &state); // Chỉ vắt đúng 64 byte
}

void Crypto::VNExos::sha256(uint8_t h[32], const uint8_t* in, uint64_t inlen)
{
  Crypto::Keccak::State state;
  init(&state, 136); // SHA3-256 có tỷ lệ = 136 byte (1088 bit)
  absorb(&state, in, inlen);
  finalize(&state, 0x25);
  squeeze(h, 32, &state); // Chỉ vắt đúng 32 byte
}

void Crypto::VNExos::sha512(uint8_t h[64], const uint8_t* in, uint64_t inlen)
{
  Crypto::Keccak::State state;
  init(&state, 72); // SHA3-512 có tỷ lệ = 72 byte (576 bit)
  absorb(&state, in, inlen);
  finalize(&state, 0x25);
  squeeze(h, 64, &state); // Chỉ vắt đúng 64 byte
}

void Crypto::VNExos::sha1024(uint8_t h[128], const uint8_t* in, uint64_t inlen)
{
  Crypto::Keccak::State state;
  init(&state, 72); // SHA3-512 có tỷ lệ = 72 byte (576 bit)
  absorb(&state, in, inlen);
  finalize(&state, 0x25);
  squeeze(h, 128, &state); // Chỉ vắt đúng 128 byte
}
