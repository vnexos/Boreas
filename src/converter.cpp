/**
 * Copyright (c) 2026 VNExos
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file converter.cpp
 * @brief Triển khai các thuật toán chuyển đổi chuỗi.
 */
#include "converter.hpp"
#include <cstdint>

std::string Converter::WStringToUtf8(const std::wstring& wstr)
{
  std::string out;
  // Tối ưu hiệu năng: Dự đoán trước kích thước tối thiểu để tránh reallocation
  out.reserve(wstr.size());

  for (wchar_t cp : wstr)
  {
    if (cp <= 0x7F)
    {
      out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF)
    {
      out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF)
    {
      out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (static_cast<uint32_t>(cp) <= 0x10FFFF)
    {
      out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else
    {
      out.push_back('?'); // Ký tự không hợp lệ
    }
  }
  return out;
}

std::wstring Converter::Utf8ToWString(const std::string& str)
{
  std::wstring dest;
  dest.reserve(str.size()); // Dự phòng dung lượng tối đa bằng size của chuỗi UTF-8

  size_t i   = 0;
  size_t len = str.size();

  while (i < len)
  {
    unsigned char byte = static_cast<unsigned char>(str[i]);
    wchar_t       codePoint;
    int           bytesToRead;

    if ((byte & 0x80) == 0)
    {
      codePoint   = byte;
      bytesToRead = 1;
    } else if ((byte & 0xE0) == 0xC0)
    {
      codePoint   = byte & 0x1F;
      bytesToRead = 2;
    } else if ((byte & 0xF0) == 0xE0)
    {
      codePoint   = byte & 0x0F;
      bytesToRead = 3;
    } else if ((byte & 0xF8) == 0xF0)
    {
      codePoint   = byte & 0x07;
      bytesToRead = 4;
    } else
    {
      dest.push_back(static_cast<wchar_t>(byte));
      ++i;
      continue;
    }

    if (i + bytesToRead > len)
    {
      dest.push_back(static_cast<wchar_t>(byte));
      ++i;
      continue;
    }

    bool valid = true;
    for (int j = 1; j < bytesToRead; ++j)
    {
      if ((static_cast<unsigned char>(str[i + j]) & 0xC0) != 0x80)
      {
        valid = false;
        break;
      }
      codePoint = (codePoint << 6) | (static_cast<unsigned char>(str[i + j]) & 0x3F);
    }

    if (valid)
    {
      dest.push_back(codePoint);
      i += bytesToRead;
    } else
    {
      dest.push_back(static_cast<wchar_t>(byte));
      ++i;
    }
  }
  return dest;
}
