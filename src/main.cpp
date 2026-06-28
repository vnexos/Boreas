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
#include <vector>

using namespace Crypto;

std::wstring ToWString(const char* str)
{
  if (!str) return L"";

  size_t len = std::mbstowcs(nullptr, str, 0);
  if (len == static_cast<size_t>(-1))
  {
    return L""; // Chuỗi chứa ký tự lỗi
  }

  std::wstring wstr(len, L'\0');
  std::mbstowcs(&wstr[0], str, len + 1);

  return wstr;
}

// Hàm tiện ích để in mảng byte dạng Thập lục phân để dễ so sánh
void print_hex(const uint8_t* data, uint64_t len)
{
  uint64_t lines = len / 0x10 + 1;

  std::wcout << "\x1b[38;5;10m        ";
  for (uint8_t i = 0; i < 0x10; ++i)
    std::wcout << "  " << std::hex << std::setw(2) << std::setfill(L'0') << i;

  std::wcout << "\x1b[0m" << std::endl;

  uint64_t tmpIndex;
  for (uint64_t i = 0; i < lines; ++i)
  {
    std::wcout << L"\x1b[38;5;10m" << std::hex << std::setw(8) << std::setfill(L'0') << (int)i << L"\x1b[0m";
    for (uint64_t j = 0; j < 0x10 && (tmpIndex = i * 0x10 + j) < len; ++j)
    {
      std::wcout << "  " << std::setw(2) << std::setfill(L'0') << (int)data[tmpIndex];
    }
    std::wcout << "\x1b[0m" << std::endl;
  }
  std::wcout << std::endl
             << std::dec << std::setfill(L' ');
}

void printUsage(const char* prog)
{
  wprintf(L"\n");
  wprintf(L"  ╔═════════════════════════════════════════════╗\n");
  wprintf(L"  ║ VNExos Ám Băng                              ║\n");
  wprintf(L"  ║ ML-KEM-1024 (Kyber) + ML-DSA-87 (Dilithium) ║\n");
  wprintf(L"  ╚═════════════════════════════════════════════╝\n");
  wprintf(L"Sử dụng:\n");
  wprintf(L"[*] Mã hóa tệp: %s -encrypt\n", prog);
  wprintf(L"    -g <tệp khóa bí mật> <tệp khóa công khai>    Tạo cặp khóa Kyber.\n");
  wprintf(L"    -e <tệp khóa công khai> <tệp vào> <tệp ra>   Mã hóa tệp bằng khóa công khai\n");
  wprintf(L"                                                 Kyber kết hợp AES-256.\n");
  wprintf(L"    -d <tệp khóa bí mật> <tệp vào> <tệp ra>      Giải mã tệp bằng khóa bí mật\n");
  wprintf(L"                                                 Kyber kết hợp AES-256.\n");
  wprintf(L"[*] Ký tệp:     %s -sign\n", prog);
}

bool bDumpFlag = false;

int main(int argc, char* argv[])
{
  // Cài đặt để chương trình có thể hoạt động tốt với tiếng Việt
  std::setlocale(LC_ALL, "C.UTF-8");
  if (argc < 2)
  {
    printUsage(argv[0]);
    return 1;
  }

  // Gieo hạt cho hàm tạo số ngẫu nhiên
  std::random_device rd;
  uint32_t           real_seed[8];
  for (int i = 0; i < 8; ++i)
  {
    real_seed[i] = rd();
  }
  randombytes_stir(reinterpret_cast<const uint8_t*>(real_seed), sizeof(real_seed));

  std::vector<std::wstring> cleanArgv;
  cleanArgv.push_back(ToWString(argv[0]));

  for (int i = 1; i < argc; ++i)
  {
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
      bDumpFlag = true;
    else
      cleanArgv.push_back(ToWString(argv[i]));
  }

  if (cleanArgv[1].compare(L"-encrypt") == 0 && cleanArgv.size() >= 3) // Tập lệnh mã hóa
  {
    if (cleanArgv[2].compare(L"-g") == 0 && cleanArgv.size() == 5)     // Tạo cặp khóa
    {
      return !Encrypt::generateKey(cleanArgv[3], cleanArgv[4]);
    } else if (cleanArgv[2].compare(L"-e") == 0 && cleanArgv.size() == 6) // Mã hóa tệp
    {
      return !Encrypt::encryptFile(cleanArgv[3], cleanArgv[4], cleanArgv[5]);
    } else if (cleanArgv[2].compare(L"-d") == 0 && cleanArgv.size() == 6) // Giải mã tệp
    {
      return !Encrypt::decryptFile(cleanArgv[3], cleanArgv[4], cleanArgv[5]);
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