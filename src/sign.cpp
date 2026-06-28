/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file sign.cpp
 * @brief Triển khai thuật toán ký/xác thực tệp cấp cao.
 */
#include "sign.hpp"
#include "converter.hpp"
#include "file.hpp"
#include "sig/dilithium.hpp"
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
#include <vector>

#define RETURN_BYTES(x)                                             \
  std::vector<uint8_t> res;                                         \
  auto                 value      = (x);                            \
  size_t               bytesCount = sizeof(value);                  \
  res.reserve(bytesCount);                                          \
  for (int i = static_cast<int>(bytesCount) - 1; i >= 0; --i)       \
  {                                                                 \
    res.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF)); \
  }                                                                 \
  return res;

void dump(const uint8_t* data, const uint64_t len, const std::wstring label = std::wstring());

/**
 * Định dạng của khối siêu dữ liệu
 *   [8 byte: mã nhận diện 'V', 'N', 'E', 'P', 'Q', 0, 0, 0]
 *   [8 byte: Thời gian cấp (unix timestamp, big-endian)]
 *   [8 byte: Thời gian hết hạn (unix timestamp, big-endian)]
 *   [2 byte: Độ dài tên công ty (big-endian)][tên công ty]
 *   [2 byte: Độ dài địa chỉ Email (big-endian)][địa chỉ email]
 *   [2 byte: Độ dài tên quốc gia (big-endian)][tên quốc gia]
 *   [2 byte: Độ dài mô tả (big-endian)][mô tả]
 */
struct SignerMeta
{
  uint64_t     issuedAt  = 0;
  uint64_t     expiredAt = 0;
  std::wstring company;
  std::wstring email;
  std::wstring country;
  std::wstring description;

  static constexpr uint64_t NEVER_EXPIRES = UINT64_MAX;

  bool is_expired() const
  {
    if (expiredAt == NEVER_EXPIRES)
      return false;
    return (uint64_t)time(NULL) > expiredAt;
  }

  bool is_perpetual() const
  {
    return expiredAt == NEVER_EXPIRES;
  }

  std::vector<uint8_t> toBytes() const
  {
    std::vector<uint8_t> result;

    std::vector<uint8_t> u8company     = stringToMetadataBytes(Converter::WStringToUtf8(company));
    std::vector<uint8_t> u8email       = stringToMetadataBytes(Converter::WStringToUtf8(email));
    std::vector<uint8_t> u8country     = stringToMetadataBytes(Converter::WStringToUtf8(country));
    std::vector<uint8_t> u8description = stringToMetadataBytes(Converter::WStringToUtf8(description));

    // 24 byte cho mã nhận diện, ngày cấp phát và ngày hết hạn
    // 8 byte tổng cộng để cho kích thước của 4 thông tin24 + 8 + u8company.size() + u8email.size() + u8country.size() + u8description.size()
    result.reserve(
        24 + 8 + u8company.size() + u8email.size() + u8country.size() + u8description.size());

    result.insert(
        result.end(),
        {
            'V',
            'N',
            'E',
            'P',
            'Q',
            0,
            0,
            0,
        });

    std::vector<uint8_t> issuedByte  = bigEndian8(issuedAt);
    std::vector<uint8_t> expiredByte = bigEndian8(expiredAt);

    // Thêm mốc thời gian
    result.insert(result.end(), issuedByte.begin(), issuedByte.end());
    result.insert(result.end(), expiredByte.begin(), expiredByte.end());

    // Thêm thông tin công ty
    result.insert(result.end(), u8company.begin(), u8company.end());
    result.insert(result.end(), u8email.begin(), u8email.end());
    result.insert(result.end(), u8country.begin(), u8country.end());
    result.insert(result.end(), u8description.begin(), u8description.end());

    return result;
  }

  static std::vector<uint8_t> bigEndian8(uint64_t n)
  {
    RETURN_BYTES(n);
  }

  static std::vector<uint8_t> bigEndian2(uint16_t n)
  {
    RETURN_BYTES(n);
  }

  static std::vector<uint8_t> stringToMetadataBytes(const std::string& str)
  {
    std::vector<uint8_t> res;

    res.reserve(2 + str.size());
    std::vector<uint8_t> tmp = bigEndian2(static_cast<uint16_t>(str.size()));
    res.insert(res.end(), tmp.begin(), tmp.end());
    res.insert(res.end(), str.begin(), str.end());

    return res;
  }

  /* Định dạng mốc thời gian thành "YYYY-MM-DD HH:MM:SS UTC" */
  static std::wstring formatTime(uint64_t ts)
  {
    if (ts == NEVER_EXPIRES)
      return L"Never (perpetual)";
    time_t     t  = (time_t)ts;
    struct tm* tm = gmtime(&t);
    char       buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", tm);
    return Converter::Utf8ToWString(std::string(buf));
  }
};

static std::wstring promptLine(const std::wstring& label)
{
  std::wstring line;
  std::wcout << L"    " << label << ": ";
  fflush(stdout);
  std::getline(std::wcin, line);
  return line;
}

bool Sign::generateKey(const std::wstring& secKeyPath, const std::wstring& pubKeyPath)
{
  wprintf(L"[+] Đang tạo cặp khóa Dilithium5...\n");
  wprintf(L"[+] Vui lòng nhập thông tin người ký: \n");

  SignerMeta metadata;
  metadata.company     = promptLine(L"Công ty      ");
  metadata.email       = promptLine(L"Địa chỉ Email");
  metadata.country     = promptLine(L"Quốc gia     ");
  metadata.description = promptLine(L"Mô tả        ");

  std::wstring daysString =
      promptLine(L"Khoảng thời gian hiệu lực (0 = vĩnh viễn, mặc định: 365)");
  int64_t validityDays = 365;
  if (!daysString.empty())
  {
    validityDays = atoi(Converter::WStringToUtf8(daysString).c_str());
    if (validityDays < 0)
    {
      wprintf(L"[-] Khoảng thời gian không hợp lệ, lấy mặc định là 365 ngày.\n");
      validityDays = 365;
    }
  }

  metadata.issuedAt = (uint64_t)time(NULL);
  if (!validityDays)
    metadata.expiredAt = UINT64_MAX;
  else
    metadata.expiredAt = metadata.issuedAt + (uint64_t)validityDays * 86400;

  auto rawData = metadata.toBytes();
  dump(rawData.data(), rawData.size(), L"Thông tin thô");

  uint8_t pk[DILITHIUM_PUBLICKEYBYTES];
  uint8_t sk[DILITHIUM_SECRETKEYBYTES];

  // Tạo cặp khóa
  Dilithium::generateKeyPair(pk, sk);

  // Xuất ra tệp khóa riêng tư: [khóa thô][siêu dữ liệu]
  {
    File::Content skFile(sk, sk + DILITHIUM_SECRETKEYBYTES);
    skFile.insert(skFile.end(), rawData.begin(), rawData.end());
    if (!File::Write(secKeyPath, skFile))
      return false;
    std::wcout << L"[+] Khóa riêng tư  được lưu vào: " << secKeyPath
               << L" (" << (DILITHIUM_SECRETKEYBYTES + rawData.size()) << L" byte)"
               << std::endl;
    dump(skFile.data(), skFile.size());
  }

  // Xuất ra tệp khóa công khai: [khóa thô][siêu dữ liệu]
  {
    File::Content pkFile(pk, pk + DILITHIUM_PUBLICKEYBYTES);
    pkFile.insert(pkFile.end(), rawData.begin(), rawData.end());
    if (!File::Write(pubKeyPath, pkFile))
      return false;
    std::wcout << L"[+] Khóa công khai được lưu vào: " << pubKeyPath
               << L" (" << (DILITHIUM_PUBLICKEYBYTES + rawData.size()) << L" byte)"
               << std::endl;
    dump(pkFile.data(), pkFile.size());
  }

  std::wcout << L"[+] Người ký    : " << metadata.company
             << L" <" << metadata.email
             << L"> [" << metadata.country << L"]"
             << std::endl;

  std::wcout << L"[+] Ngày cấp    : " << SignerMeta::formatTime(metadata.issuedAt) << std::endl;

  if (validityDays == 0)
  {
    std::wcout << L"[+] Ngày hết hạn: (Không bao giờ)" << std::endl;
  } else
  {
    std::wcout << L"[+] Ngày hết hạn: " << SignerMeta::formatTime(metadata.expiredAt)
               << L" (" << validityDays << L" ngày)"
               << std::endl;
  }

  return true;
}