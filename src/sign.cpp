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
#include "crypto/aes256.hpp"
#include "crypto/randombytes.hpp"
#include "crypto/sha3.hpp"
#include "file.hpp"
#include "sig/dilithium.hpp"
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <string.h>
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

extern std::wstring signType;
extern uint8_t      dilithiumKeyType;

void dump(const uint8_t* data, const uint64_t len, const std::wstring label = std::wstring());

/**
 * Định dạng của khối siêu dữ liệu
 *   [32 byte: Mã băm của khóa hiện tại][32 byte: Mã băm của khóa cha]
 * [
 *   [8  byte: Thời gian cấp (unix timestamp, big-endian)]
 *   [8  byte: Thời gian hết hạn (unix timestamp, big-endian)]
 *   [2  byte: Độ dài tên tổ chức (big-endian)][tên tổ chức]
 *   [2  byte: Độ dài địa chỉ Email (big-endian)][địa chỉ email]
 *   [2  byte: Độ dài tên quốc gia (big-endian)][tên quốc gia]
 *   [2  byte: Độ dài mô tả (big-endian)][mô tả]
 * ] Vùng bị mã hóa
 *   [16 byte: Mảng khởi tạo của AES]
 *   [8  byte: Độ dài khối siêu dữ liệu (big-endian)]
 *   [8  byte: mã nhận diện 'V', 'N', 'E', 'P', 'Q', 0, 0, x]
 */
struct SignerMeta
{
  uint64_t     issuedAt  = 0;
  uint64_t     expiredAt = 0;
  uint8_t      currentKey[32];
  uint8_t      parentKey[32];
  std::wstring organization;
  std::wstring email;
  std::wstring country;
  std::wstring description;

  static constexpr uint64_t NEVER_EXPIRES = UINT64_MAX;

  void clean()
  {
    memset(currentKey, 0, 32);
    memset(parentKey, 0, 32);
  }

  bool IsExpired() const
  {
    if (expiredAt == NEVER_EXPIRES)
      return false;
    return (uint64_t)time(NULL) > expiredAt;
  }

  bool IsPerpetual() const
  {
    return expiredAt == NEVER_EXPIRES;
  }

  std::vector<uint8_t> toBytes() const
  {
    std::vector<uint8_t> result;

    std::vector<uint8_t> u8organization = stringToMetadataBytes(Converter::WStringToUtf8(organization));
    std::vector<uint8_t> u8email        = stringToMetadataBytes(Converter::WStringToUtf8(email));
    std::vector<uint8_t> u8country      = stringToMetadataBytes(Converter::WStringToUtf8(country));
    std::vector<uint8_t> u8description  = stringToMetadataBytes(Converter::WStringToUtf8(description));

    // 64 byte cho SHA-256 của khóa và của khóa cha
    // 16 byte cho ngày cấp phát và ngày hết hạn
    // x byte  tổng cộng để cho kích thước của 4 thông tin: u8organization.size() + u8email.size() + u8country.size() + u8description.size()
    // 8 byte  Kích thước khối siêu dữ liệu
    // 8 byte  cho mã nhận diện
    // 16 byte chứa mảng khởi tạo cho thuật toán AES (AES256_BLOCKLEN)
    result.reserve(
        8 + 64 + 16 + 8 + AES256_BLOCKLEN + u8organization.size() + u8email.size() + u8country.size() + u8description.size());

    result.insert(result.end(), currentKey, currentKey + sizeof(currentKey));
    result.insert(result.end(), parentKey, parentKey + sizeof(parentKey));

    std::vector<uint8_t> issuedByte  = bigEndian8(issuedAt);
    std::vector<uint8_t> expiredByte = bigEndian8(expiredAt);

    // Thêm mốc thời gian
    result.insert(result.end(), issuedByte.begin(), issuedByte.end());
    result.insert(result.end(), expiredByte.begin(), expiredByte.end());

    // Thêm thông tin công ty
    result.insert(result.end(), u8organization.begin(), u8organization.end());
    result.insert(result.end(), u8email.begin(), u8email.end());
    result.insert(result.end(), u8country.begin(), u8country.end());
    result.insert(result.end(), u8description.begin(), u8description.end());

    Crypto::AES256::AES256Context context;
    uint8_t                       iv[AES256_BLOCKLEN];
    Crypto::randombytes(iv, sizeof(iv));

    Crypto::AES256::init(&context, currentKey);
    Crypto::AES256::counter(&context, iv, result.data() + 64, result.data() + 64, result.size() - 64);

    result.insert(result.end(), iv, iv + sizeof(iv));

    std::vector<uint8_t> metadataSize = bigEndian8(result.size());
    result.insert(result.end(), metadataSize.begin(), metadataSize.end());

    // Mã nhận diện cho siêu dữ liệu "VNExos Post Quantum"
    result.insert(
        result.end(),
        {
            dilithiumKeyType,
            0,
            0,
            'Q',
            'P',
            'E',
            'N',
            'V',
        });

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

  static uint64_t getBigEndian8(uint8_t*& arr)
  {
    uint64_t res = 0;
    for (uint8_t i = 0; i < 8; ++i)
      res = (res << 8) | *(arr++);
    return res;
  }

  static uint16_t getBigEndian2(uint8_t*& arr)
  {
    uint8_t high = *arr++;
    uint8_t low  = *arr++;
    return (static_cast<uint16_t>(high) << 8) | low;
  }

  static std::wstring getString(uint8_t*& arr)
  {
    uint16_t    strSize = getBigEndian2(arr);
    std::string res;
    for (uint16_t i = 0; i < strSize; ++i)
      res.push_back(*(arr++));

    return Converter::Utf8ToWString(res);
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

static bool readCertMetadata(const std::wstring& certPath, SignerMeta& metadata)
{
// Mở tệp ở chế độ đọc nhị phân và dịch con trỏ xuống cuối tệp (std::ios::ate) để lấy kích thước
#if defined(_WIN32)
  std::ifstream inp(certPath, std::ios::in | std::ios::binary | std::ios::ate);
#else
  std::string   utf8FileName(certPath.begin(), certPath.end());
  std::ifstream inp(utf8FileName, std::ios::in | std::ios::binary | std::ios::ate);
#endif

  if (!inp)
  {
    std::wcout << "[-] Không thể mở tệp khóa để đọc." << std::endl;
    return false;
  }

  std::streamsize fileSize = inp.tellg();
  if (fileSize < 120)
  {
    std::wcout << "[-] Tệp quá nhỏ, không đúng cấu trúc!" << std::endl;
    return false;
  }

  // Kiểm tra mã nhận diện
  uint64_t magic;
  inp.seekg(fileSize - 8);
  inp.read(reinterpret_cast<char*>(&magic), sizeof(magic));

  if ((magic & ~(uint64_t)0xff) != 0x564e455051000000)
  {
    std::wcout << "[-] Mã nhận diện không hợp lệ." << std::endl;
    return false;
  }

  // Kiểm tra và lấy kích thước siêu dữ liệu
  uint8_t sizeBytes[8];
  inp.seekg(fileSize - 16);
  inp.read(reinterpret_cast<char*>(sizeBytes), sizeof(sizeBytes));

  uint64_t metadataSize = 0;
  for (int i = 0; i < 8; ++i)
  {
    metadataSize = (metadataSize << 8) | static_cast<uint64_t>(sizeBytes[i]);
  }

  if (metadataSize > static_cast<uint64_t>(fileSize) || metadataSize < 120)
  {
    std::wcout << "[-] Kích thước siêu dữ liệu không hợp lệ." << std::endl;
    return false;
  }

  // Tính toán mốc bắt đầu của khối Siêu dữ liệu tính từ đầu tệp
  std::streampos metaStartOffset = fileSize - 16 - static_cast<std::streamsize>(metadataSize);

  // Đọc các mã định dạng
  inp.seekg(metaStartOffset);
  inp.read(reinterpret_cast<char*>(metadata.currentKey), sizeof(metadata.currentKey));
  inp.read(reinterpret_cast<char*>(metadata.parentKey), sizeof(metadata.parentKey));

  // Đọc phần dữ liệu bị mã hóa
  uint64_t             encryptedSize = metadataSize - 64 - AES256_BLOCKLEN;
  std::vector<uint8_t> encryptedPart(encryptedSize);
  inp.read(reinterpret_cast<char*>(encryptedPart.data()), encryptedSize);

  // Đọc mảng khởi tạo AES
  uint8_t iv[AES256_BLOCKLEN];
  inp.read(reinterpret_cast<char*>(iv), sizeof(iv));

  // Giải mã khối siêu dữ liệu
  std::vector<uint8_t> plaintext(encryptedSize);

  Crypto::AES256::AES256Context context;
  Crypto::AES256::init(&context, metadata.currentKey);
  Crypto::AES256::counter(&context, iv, plaintext.data(), encryptedPart.data(), encryptedSize);

  uint8_t* plaintextPtr = plaintext.data();

  // Đọc mã byte thô vào cấu trúc dữ liệu
  metadata.issuedAt     = SignerMeta::getBigEndian8(plaintextPtr);
  metadata.expiredAt    = SignerMeta::getBigEndian8(plaintextPtr);
  metadata.organization = SignerMeta::getString(plaintextPtr);
  metadata.email        = SignerMeta::getString(plaintextPtr);
  metadata.country      = SignerMeta::getString(plaintextPtr);
  metadata.description  = SignerMeta::getString(plaintextPtr);

  return true;
}

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
  metadata.clean();

  metadata.organization = promptLine(L"Tổ chức      ");
  metadata.email        = promptLine(L"Địa chỉ Email");
  metadata.country      = promptLine(L"Quốc gia     ");
  metadata.description  = promptLine(L"Mô tả        ");

  std::wstring daysString   = promptLine(L"Khoảng thời gian hiệu lực (0 = vĩnh viễn, mặc định: 365)");
  int64_t      validityDays = 365;
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
    metadata.expiredAt = SignerMeta::NEVER_EXPIRES;
  else
    metadata.expiredAt = metadata.issuedAt + (uint64_t)validityDays * 86400;

  uint8_t pk[DILITHIUM_PUBLICKEYBYTES];
  uint8_t sk[DILITHIUM_SECRETKEYBYTES];

  // Tạo cặp khóa
  Dilithium::generateKeyPair(pk, sk);

  Crypto::VNExos::sha256(metadata.currentKey, sk, DILITHIUM_SECRETKEYBYTES);
  auto rawData = metadata.toBytes();

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

  Crypto::VNExos::sha256(metadata.currentKey, pk, DILITHIUM_PUBLICKEYBYTES);
  rawData = metadata.toBytes();

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

  std::wcout << L"[+] Người ký    : " << metadata.organization
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

/**
 * Định dạng của tệp sau khi ký:
 * - Đối với khóa phân cấp:
 *     [2592 byte: Mảng khóa công khai]
 *     [x    byte: Khối siêu dữ liệu đã được chỉnh sửa]
 *     [4627 byte: Chữ ký]
 * - Đối với tệp mặc định (thêm siêu dữ liệu vào cuối tệp):
 *     [32   byte: Mã băm của khóa ký]
 *   [
 *     [8    byte: Thời gian cấp (unix timestamp, big-endian)]
 *     [8    byte: Thời gian hết hạn (unix timestamp, big-endian)]
 *     [2    byte: Độ dài tên tổ chức (big-endian)][tên tổ chức]
 *     [2    byte: Độ dài địa chỉ Email (big-endian)][địa chỉ email]
 *     [2    byte: Độ dài tên quốc gia (big-endian)][tên quốc gia]
 *     [2    byte: Độ dài mô tả (big-endian)][mô tả]
 *   ] Vùng bị mã hóa
 *     [16   byte: Mảng khởi tạo của AES]
 *     [4627 byte: Chữ ký]
 *     [8    byte: Độ dài khối siêu dữ liệu (big-endian)]
 *     [8    byte: mã nhận diện 'V', 'N', 'E', 'P', 'Q', 'S', 0, x]
 */
bool Sign::signFile(
    const std::wstring& secKeyPath,
    const std::wstring& pubKeyPath,
    const std::wstring& inPath,
    const std::wstring& outPath)
{
  SignerMeta metadata;
  std::wcout << readCertMetadata(pubKeyPath, metadata) << std::endl;

  if (signType.compare(L"cert") == 0)
  {
  }
  return true;
}