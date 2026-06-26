/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file file.cpp
 * @brief Triển khai các chức năng đọc/ghi và xử lý tệp tin.
 */
#include "file.hpp"
#include <fstream>

bool File::Write(const std::wstring& fileName, const File::Content& fileContent)
{
  // Mở tệp ở chế độ ghi nhị phân (std::ios::binary)
  // Nếu dùng trên Windows, std::ofstream hỗ trợ nhận std::wstring trực tiếp
#if defined(_WIN32)
  std::ofstream out(fileName, std::ios::out | std::ios::binary);
#else
  std::string   utf8FileName(fileName.begin(), fileName.end());
  std::ofstream out(utf8FileName, std::ios::out | std::ios::binary);
#endif

  if (!out)
    return false;

  // Ghi toàn bộ mảng byte vào tệp
  if (!fileContent.empty())
    out.write(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

  out.close();
  return true;
}

bool File::Read(const std::wstring& fileName, File::Content& fileContent)
{

  // Mở tệp ở chế độ đọc nhị phân và dịch con trỏ xuống cuối tệp (std::ios::ate) để lấy kích thước
#if defined(_WIN32)
  std::ifstream inp(fileName, std::ios::in | std::ios::binary | std::ios::ate);
#else
  std::string   utf8FileName(fileName.begin(), fileName.end());
  std::ifstream inp(utf8FileName, std::ios::in | std::ios::binary | std::ios::ate);
#endif

  // Trả về vector rỗng nếu không mở được tệp
  if (!inp)
    return false;

  // Lấy kích thước tệp dựa vào vị trí của con trỏ hiện tại
  std::streamsize fileSize = inp.tellg();

  if (fileSize > 0)
  {
    // Cấp phát trước bộ nhớ vector để tối ưu hiệu năng (tránh cấp phát nhiều lần)
    fileContent.resize(static_cast<size_t>(fileSize));

    // Đưa con trỏ về vị trí đầu tệp để bắt đầu đọc
    inp.seekg(0, std::ios::beg);

    // Đọc toàn bộ dữ liệu vào vector
    inp.read(reinterpret_cast<char*>(fileContent.data()), fileSize);
  }

  inp.close();
  return true;
}