/**
 * Copyright (c) 2026 VNExos
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file utils.cpp
 * @brief Triển khai các tiện ích hiển thị chi tiết (verbose/hexdump).
 */
#include "utils.hpp"
#include <iomanip>
#include <iostream>

void print_hex(const uint8_t* data, uint64_t len)
{
  if (!data || len == 0)
    return;

  uint64_t lines = (len + 0x0F) / 0x10;

  std::wcout << L"\x1b[38;5;10m        ";
  for (uint8_t i = 0; i < 0x10; ++i)
    std::wcout << L"  " << std::hex << std::setw(2) << std::setfill(L'0') << static_cast<int>(i);

  std::wcout << L"\x1b[0m" << std::endl;

  uint64_t tmpIndex;
  for (uint64_t i = 0; i < lines; ++i)
  {
    std::wcout << L"\x1b[38;5;10m" << std::hex << std::setw(8) << std::setfill(L'0') << (i * 0x10) << L"\x1b[0m";
    for (uint64_t j = 0; j < 0x10 && (tmpIndex = i * 0x10 + j) < len; ++j)
    {
      std::wcout << L"  " << std::setw(2) << std::setfill(L'0') << static_cast<int>(data[tmpIndex]);
    }
    std::wcout << L"\x1b[0m" << std::endl;
  }
  std::wcout << std::endl
             << std::dec << std::setfill(L' ');
}

void dump(const uint8_t* data, const uint64_t len, const std::wstring& label)
{
  if (bDumpFlag)
  {
    if (label.empty())
      std::wcout << L"    Mã thô: " << std::endl;
    else
      std::wcout << L"    " << label << L':' << std::endl;
    print_hex(data, len);
  }
}
