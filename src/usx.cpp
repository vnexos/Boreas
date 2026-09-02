/**
 * Copyright (c) 2026 VNExos
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file usx.hpp
 * @brief Triển khai các hàm để kiểm tra, thao tác với
 * tệp Thực thi bảo mật đa kiến trúc.
 */
#include "usx.hpp"
#include "file.hpp"
#include <array>
#include <cstdint>
#include <iostream>

constexpr auto generateCRC32Table()
{
  std::array<uint32_t, 256> table{};
  for (uint32_t i = 0; i < 256; ++i)
  {
    uint32_t crc = i;
    for (int j = 0; j < 8; ++j)
    {
      if (crc & 1)
      {
        crc = (crc >> 1) ^ 0xEDB88320;
      } else
      {
        crc >>= 1;
      }
    }
    table[i] = crc;
  }
  return table;
}

inline constexpr auto CRC32_TABLE = generateCRC32Table();

static uint32_t calcCRC32(std::vector<uint8_t> bytes)
{
  uint32_t crc = 0xffffffff;
  for (uint8_t byte : bytes)
  {
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >> 8);
  }
  return (crc ^ 0xffffffff) & 0xffffffff;
}

USXHeader USX::getHeader(const std::wstring& path)
{
  File::Content content;
  if (!File::Read(path, content, sizeof(USXHeader)))
  {
    std::wcout << L"[-] Có lỗi xảy ra trong quá trình đọc tệp: " << path << std::endl;
    return USXHeader();
  }

  USXHeader* header = (USXHeader*)content.data();
  return *header;
}

bool USX::putHeader(const std::wstring& path, USXHeader* header)
{
  std::vector<uint8_t> data((uint8_t*)header, ((uint8_t*)header) + (sizeof(USXHeader) - 4));

  uint32_t crc        = calcCRC32(data);
  header->HeaderCRC32 = crc;

  File::Content rawData((uint8_t*)header, ((uint8_t*)header) + sizeof(USXHeader));
  if (!File::Write(path, rawData, 0))
  {
    std::wcout << L"[-] Có lỗi xảy ra trong quá trình ghi tệp: " << path << std::endl;
    return false;
  }

  return true;
}

bool USX::verifyHeader(const std::wstring& path, USXHeader* _header)
{
  File::Content content;
  if (!File::Read(path, content, sizeof(USXHeader)))
  {
    std::wcout << L"[-] Có lỗi xảy ra trong quá trình đọc tệp: " << path << std::endl;
    return false;
  }

  USXHeader* header = (USXHeader*)content.data();
  if (_header)
    *_header = *header;

  uint32_t crc32           = header->HeaderCRC32;
  uint32_t magicDoubleWord = *(uint32_t*)(header->MagicBytes);

  if (magicDoubleWord != 0x585355)
  {
    return false;
  }

  content.resize(sizeof(USXHeader) - 4);
  uint32_t crc32ToCheck = calcCRC32(content);

  return (crc32 == crc32ToCheck);
}

USXSecurity USX::getSecurityTable(const std::wstring& path)
{
  USXHeader     header = getHeader(path);
  uint64_t      offset = header.SecurityOffset;
  File::Content content;
  if (!File::Read(path, content, sizeof(USXSecurity), offset))
  {
    std::wcout << L"[-] Có lỗi xảy ra trong quá trình đọc tệp: " << path << std::endl;
    return USXSecurity();
  }

  USXSecurity* sec = (USXSecurity*)content.data();
  return *sec;
}

bool USX::putSecurityTable(const std::wstring& path, const USXSecurity* security)
{
  USXHeader header = getHeader(path);

  uint64_t offset = header.SecurityOffset;
  uint32_t size   = header.SecuritySize;

  const uint8_t* secBytes = reinterpret_cast<const uint8_t*>(security);
  File::Content  data(secBytes, secBytes + size);

  if (!File::Write(path, data, offset))
  {
    std::wcout << L"[-] Có lỗi xảy trong quá trình ghi vào bảng Bảo mật: " << path << std::endl;
    return false;
  }

  return true;
}

bool USX::getSections(const std::wstring& path, std::vector<USXSection>& sections)
{
  USXHeader header = getHeader(path);

  sections.clear();

  if (header.ArchTableCount == 0)
    return true;

  File::Content rawArchData;
  if (!File::Read(path, rawArchData, header.ArchTableSize * header.ArchTableCount, header.ArchTableOffset))
  {
    std::wcout << L"[-] Có lỗi xảy ra trong quá trình đọc dữ liệu Kiến trúc: " << path << std::endl;
    return false;
  }

  uint8_t* archPtr = rawArchData.data();
  for (uint16_t i = 0; i < header.ArchTableCount; ++i)
  {
    USXArch* arch = (USXArch*)archPtr;

    if (arch->SectionTableCount > 0)
    {
      File::Content rawSectionData;
      if (!File::Read(path, rawSectionData, arch->SectionTableSize * arch->SectionTableCount, arch->SectionTableOffset))
      {
        std::wcout << L"[-] Có lỗi xảy ra trong quá trình đọc dữ liệu Phân vùng: " << path << std::endl;
        return false;
      }

      uint8_t* sectionPtr = rawSectionData.data();
      for (uint16_t j = 0; j < arch->SectionTableCount; ++j)
      {
        sections.push_back(*(USXSection*)sectionPtr);
        sectionPtr += arch->SectionTableSize;
      }
    }

    archPtr += header.ArchTableSize;
  }

  return true;
}
