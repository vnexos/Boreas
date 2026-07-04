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
#include "crypto/sha3.hpp"
#include <filesystem>
#include <fstream>

bool File::Write(const std::wstring& filePath, const File::Content& fileContent, uint64_t offset)
{
  // Mở tệp ở chế độ ghi nhị phân (std::ios::binary)
  // Nếu dùng trên Windows, std::ofstream hỗ trợ nhận std::wstring trực tiếp
#if defined(_WIN32)
  std::ofstream out(filePath, (offset ? std::ios::in | std::ios::out : std::ios::out) | std::ios::binary);
#else
  std::string   utf8FilePath(filePath.begin(), filePath.end());
  std::ofstream out(utf8FilePath, (offset ? std::ios::in | std::ios::out : std::ios::out) | std::ios::binary);
#endif

  if (!out)
    return false;

  if (offset != 0)
    out.seekp(offset, std::ios::beg);
  // Ghi toàn bộ mảng byte vào tệp
  if (!fileContent.empty())
    out.write(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

  out.close();
  return true;
}

bool File::Append(const std::wstring& filePath, const Content& fileContent)
{
  // Mở tệp ở chế độ ghi nhị phân (std::ios::binary)
  // Nếu dùng trên Windows, std::ofstream hỗ trợ nhận std::wstring trực tiếp
#if defined(_WIN32)
  std::ofstream out(filePath, std::ios::app | std::ios::binary);
#else
  std::string   utf8FilePath(filePath.begin(), filePath.end());
  std::ofstream out(utf8FilePath, std::ios::app | std::ios::binary);
#endif

  if (!out)
    return false;

  if (!fileContent.empty())
    out.write(reinterpret_cast<const char*>(fileContent.data()), fileContent.size());

  out.close();
  return true;
}

bool File::Read(const std::wstring& filePath, File::Content& fileContent)
{
  // Mở tệp ở chế độ đọc nhị phân và dịch con trỏ xuống cuối tệp (std::ios::ate) để lấy kích thước
#if defined(_WIN32)
  std::ifstream inp(filePath, std::ios::in | std::ios::binary | std::ios::ate);
#else
  std::string   utf8FilePath(filePath.begin(), filePath.end());
  std::ifstream inp(utf8FilePath, std::ios::in | std::ios::binary | std::ios::ate);
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

bool File::Hash(const std::wstring& filePath, std::vector<uint8_t>& outputHash, int type)
{
  size_t rate;
  size_t outputLen;

  switch (type)
  {
  case 256:
    rate      = 136; // 1088-bit rate -> capacity 512-bit
    outputLen = 32;  // 256-bit output
    break;
  case 512:
    rate      = 72; // 576-bit rate -> capacity 1024-bit
    outputLen = 64; // 512-bit output
    break;
  case 1024:
    rate      = 72;  // giữ theo logic gốc của bạn
    outputLen = 128; // 1024-bit output (dùng như XOF)
    break;
  default:
    return false; // type không được hỗ trợ
  }

  // Mở tệp ở chế độ đọc nhị phân
#if defined(_WIN32)
  std::ifstream inp(filePath, std::ios::in | std::ios::binary | std::ios::ate);
#else
  std::string   utf8FilePath(filePath.begin(), filePath.end());
  std::ifstream inp(utf8FilePath, std::ios::in | std::ios::binary);
#endif

  if (!inp)
    return false;

  outputHash.resize(outputLen);

  // Khởi tạo trạng thái Keccak với rate tương ứng
  Crypto::Keccak::State state;
  init(&state, rate);

  const size_t         BUFFER_SIZE = 64 * 1024;
  std::vector<uint8_t> buffer(BUFFER_SIZE);

  while (inp.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || inp.gcount() > 0)
  {
    uint64_t bytesRead = inp.gcount();
    Crypto::Keccak::absorb(&state, buffer.data(), bytesRead);
  }

  Crypto::Keccak::finalize(&state, 0x25);
  Crypto::Keccak::squeeze(outputHash.data(), outputHash.size(), &state);

  inp.close();
  return true;
}

bool File::Copy(const std::wstring& inPath, const std::wstring& outPath)
{
  try
  {
    if (inPath.compare(outPath) == 0)
      return true;
    return std::filesystem::copy_file(
        inPath,
        outPath,
        std::filesystem::copy_options::overwrite_existing);
  } catch (const std::filesystem::filesystem_error&)
  {
    return false;
  }
}

bool File::Exist(const std::wstring& path)
{
  std::error_code ec;

  bool result = std::filesystem::is_regular_file(path, ec);
  return !ec && result;
}
