/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file main.cpp
 * @brief Tệp mã nguồn chính, điểm bắt đầu thực thi chương trình.
 */
#include "crypto/randombytes.hpp"
#include "encrypt.hpp"

#include <clocale>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <random>
#include <string.h>
#include <string>

using namespace Crypto;

std::wstring ToWString(const char* str)
{
  if (!str) return L"";

  // 1. Gọi lần đầu với con trỏ nullptr để lấy kích thước chuỗi wstring cần cấp phát
  size_t len = std::mbstowcs(nullptr, str, 0);
  if (len == static_cast<size_t>(-1))
  {
    return L""; // Chuỗi chứa ký tự lỗi
  }

  // 2. Cấp phát mảng wstring với kích thước vừa tính
  std::wstring wstr(len, L'\0');

  // 3. Thực hiện chuyển đổi thực sự vào bộ đệm của wstring
  std::mbstowcs(&wstr[0], str, len + 1);

  return wstr;
}

// Hàm tiện ích để in mảng byte dạng Thập lục phân để dễ so sánh
void print_hex(const char* label, const uint8_t* data, uint64_t len)
{
  std::cout << label << ": " << std::endl;
  for (uint64_t i = 0; i < len; ++i)
  {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
  }
  std::cout << std::endl;
}

void printUsage(const char* prog)
{
  wprintf(L"\n");
  wprintf(L"  ╔═════════════════════════════════════════════╗\n");
  wprintf(L"  ║ VNExos Hậu Lượng Tử                         ║\n");
  wprintf(L"  ║ ML-KEM-1024 (Kyber) + ML-DSA-87 (Dilithium) ║\n");
  wprintf(L"  ╚═════════════════════════════════════════════╝\n");
  wprintf(L"Sử dụng:\n");
  wprintf(L"[*] Mã hóa tệp:\n");
  wprintf(L"    %s -encrypt -g <tệp khóa bí mật> <tệp khóa công khai>    Tạo cặp khóa Kyber.\n", prog);
  wprintf(L"    %s -encrypt -e <tệp khóa công khai> <tệp vào> <tệp ra>   Mã hóa tệp bằng khóa công khai Kyber kết hợp AES-256\n", prog);
  wprintf(L"    %s -encrypt -d <tệp khóa bí mật> <tệp vào> <tệp ra>      Giải mã tệp bằng khóa bí mật Kyber kết hợp AES-256.\n", prog);
}

int main(int argc, char* argv[])
{
  std::setlocale(LC_ALL, "C.UTF-8");
  if (argc < 2)
  {
    printUsage(argv[0]);
    return 1;
  }

  std::random_device rd;
  uint32_t           real_seed[8];
  for (int i = 0; i < 8; i++)
  {
    real_seed[i] = rd();
  }
  randombytes_stir(reinterpret_cast<const uint8_t*>(real_seed), sizeof(real_seed));

  if (strcmp(argv[1], "-encrypt") == 0 && argc >= 3)
  {
    if (strcmp(argv[2], "-g") == 0 && argc == 5)
    {
      return !Encrypt::generateKey(ToWString(argv[3]), ToWString(argv[4]));
    } else if (strcmp(argv[2], "-e") == 0 && argc == 6)
    {
      return !Encrypt::encryptFile(ToWString(argv[3]), ToWString(argv[4]), ToWString(argv[5]));
    } else if (strcmp(argv[2], "-d") == 0 && argc == 6)
    {
      return !Encrypt::decryptFile(ToWString(argv[3]), ToWString(argv[4]), ToWString(argv[5]));
    } else
    {
      wprintf(L"[-] Lệnh sử dụng -encrypt không hợp lệ!\n");
      printUsage(argv[0]);
      return 1;
    }
  }

  wprintf(L"[-] Không rõ lệnh hoặc sai số lượng tham số!");
  printUsage(argv[0]);
  return 0;
}