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
#include <iomanip>
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

static constexpr uint8_t rootKey[32] = {
    0x56, 0x15, 0xaf, 0xba, 0x84, 0x68, 0xaa, 0x87,
    0xb5, 0xdf, 0xd0, 0x97, 0xf2, 0x63, 0x73, 0xb6,
    0xf7, 0x69, 0x33, 0xe2, 0xa4, 0x21, 0x1f, 0xce,
    0x09, 0x4e, 0x11, 0x51, 0x74, 0xae, 0x37, 0xa9};

void dump(const uint8_t* data, const uint64_t len, const std::wstring label = std::wstring());

// Xóa sạch vùng nhớ nhạy cảm
inline void secureZeroize(void* p, size_t n)
{
  volatile uint8_t* vp = (volatile uint8_t*)p;
  while (n--)
    *vp++ = 0;
}

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
  uint8_t      parentCertHash[32];
  uint8_t      type = dilithiumKeyType;
  std::wstring organization;
  std::wstring email;
  std::wstring country;
  std::wstring description;

  static constexpr uint64_t NEVER_EXPIRES = UINT64_MAX;

  void clean()
  {
    memset(currentKey, 0, 32);
    memset(parentKey, 0, 32);
    memset(parentCertHash, 0, 32);
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

    // 64 byte cho mã băm khóa cha và mã băm chứng chỉ cha
    // 16 byte cho ngày cấp phát và ngày hết hạn
    // x byte  tổng cộng để cho kích thước của 4 thông tin: u8organization.size() + u8email.size() + u8country.size() + u8description.size()
    // 8 byte  Kích thước khối siêu dữ liệu
    // 8 byte  cho mã nhận diện
    // 16 byte chứa mảng khởi tạo cho thuật toán AES (AES256_BLOCKLEN)
    result.reserve(
        8 + 64 + 16 + 8 + AES256_BLOCKLEN + u8organization.size() + u8email.size() + u8country.size() + u8description.size());

    result.insert(result.end(), parentKey, parentKey + sizeof(parentKey));
    result.insert(result.end(), parentCertHash, parentCertHash + sizeof(parentCertHash));

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
    dump(iv, sizeof(iv), L"Mảng khởi tạo");

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
      return L"(Không bao giờ)";
    time_t     t  = (time_t)ts;
    struct tm* tm = gmtime(&t);
    char       buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", tm);
    return Converter::Utf8ToWString(std::string(buf));
  }
};

/**
 * @param certPath Đường dẫn tới tệp chứng chỉ
 * @param metadata Đầu ra của khối Siêu dữ liệu
 * @return Trả về vị trí bắt đầu của khối siêu dữ liệu
 */
static uint64_t readCertMetadata(const std::wstring& certPath, SignerMeta& metadata, bool* signedCert = 0)
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
    std::wcout << L"[-] Không thể mở tệp khóa để đọc." << std::endl;
    return 0;
  }

  std::streamsize fileSize = inp.tellg();
  if (fileSize < 120)
  {
    std::wcout << L"[-] Tệp quá nhỏ, không đúng cấu trúc!" << std::endl;
    return 0;
  }

  // Kiểm tra mã nhận diện
  uint64_t magic;
  inp.seekg(fileSize - 8);
  inp.read(reinterpret_cast<char*>(&magic), sizeof(magic));
  uint64_t oldFileSize;

  if ((magic & ~(uint64_t)0xff) != 0x564e455051000000)
  {
    // Check lại xem tệp chứng chỉ đã được ký hay chưa
    inp.seekg(fileSize - DILITHIUM_BYTES - 8);
    inp.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    if ((magic & ~(uint64_t)0xff) != 0x564e455051000000)
    {
      std::wcout << L"[-] Mã nhận diện không hợp lệ." << std::endl;
      return 0;
    }
    oldFileSize  = fileSize;
    fileSize    -= DILITHIUM_BYTES;
    if (signedCert)
      *signedCert = true;
  } else
  {
    if (signedCert)
      *signedCert = false;
  }

  // Tạm thời chưa sử dụng
  (void)oldFileSize;

  metadata.type = magic & 0xff;

  // Kiểm tra và lấy kích thước siêu dữ liệu
  uint8_t sizeBytes[8];
  inp.seekg(fileSize - 16);
  inp.read(reinterpret_cast<char*>(sizeBytes), sizeof(sizeBytes));

  uint64_t metadataSize = 0;
  for (int i = 0; i < 8; ++i)
  {
    metadataSize = (metadataSize << 8) | static_cast<uint64_t>(sizeBytes[i]);
  }

  if (metadataSize > static_cast<uint64_t>(fileSize) || metadataSize < 72)
  {
    std::wcout << L"[-] Kích thước siêu dữ liệu không hợp lệ." << std::endl;
    return 0;
  }

  // Tính toán mốc bắt đầu của khối Siêu dữ liệu tính từ đầu tệp
  std::streampos metaStartOffset = fileSize - 16 - static_cast<std::streamsize>(metadataSize);

  // Đọc các mã định dạng
  inp.seekg(metaStartOffset);
  inp.read(reinterpret_cast<char*>(metadata.parentKey), sizeof(metadata.parentKey));
  inp.read(reinterpret_cast<char*>(metadata.parentCertHash), sizeof(metadata.parentCertHash));

  // Đọc phần dữ liệu bị mã hóa
  uint64_t             encryptedSize = metadataSize - 64 - AES256_BLOCKLEN;
  std::vector<uint8_t> encryptedPart(encryptedSize);
  inp.read(reinterpret_cast<char*>(encryptedPart.data()), encryptedSize);

  // Đọc mảng khởi tạo AES
  uint8_t iv[AES256_BLOCKLEN];
  inp.read(reinterpret_cast<char*>(iv), sizeof(iv));

  // Đọc mảng khóa và băm nó ra
  inp.seekg(0);
  std::vector<uint8_t> pk(DILITHIUM_PUBLICKEYBYTES);
  inp.read(reinterpret_cast<char*>(pk.data()), pk.size());

  Crypto::VNExos::sha256(metadata.currentKey, pk.data(), pk.size());
  dump(iv, sizeof(iv), L"Mảng khởi tạo");

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

  inp.close();

  return metaStartOffset;
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

  // Xuất ra tệp khóa riêng tư: [khóa thô][siêu dữ liệu]
  {
    File::Content skFile(sk, sk + DILITHIUM_SECRETKEYBYTES);
    secureZeroize(sk, DILITHIUM_SECRETKEYBYTES);
    if (!File::Write(secKeyPath, skFile))
    {
      secureZeroize(skFile.data(), skFile.size());
      return false;
    }
    std::wcout << L"[+] Khóa riêng tư  được lưu vào: " << secKeyPath
               << L" (" << DILITHIUM_SECRETKEYBYTES << L" byte)"
               << std::endl;
    dump(skFile.data(), skFile.size());
    secureZeroize(skFile.data(), skFile.size());
  }

  Crypto::VNExos::sha256(metadata.currentKey, pk, DILITHIUM_PUBLICKEYBYTES);
  auto rawData = metadata.toBytes();

  // Xuất ra tệp chứng chỉ: [khóa thô][siêu dữ liệu]
  {
    File::Content pkFile(pk, pk + DILITHIUM_PUBLICKEYBYTES);
    pkFile.insert(pkFile.end(), rawData.begin(), rawData.end());
    if (!File::Write(pubKeyPath, pkFile))
      return false;
    std::wcout << L"[+] Chứng chỉ được lưu vào: " << pubKeyPath
               << L" (" << (DILITHIUM_PUBLICKEYBYTES + rawData.size()) << L" byte)"
               << std::endl;
    dump(pkFile.data(), pkFile.size());
    dump(metadata.currentKey, sizeof(metadata.currentKey), L"Mã băm chứng chỉ");
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

static bool signCertFile(
    const std::wstring& secKeyPath,
    const std::wstring& pubKeyPath,
    const std::wstring& inPath,
    const std::wstring& outPath,
    const SignerMeta&   metadata)
{
  (void)pubKeyPath;

  SignerMeta inMeta;
  bool       signedCert;
  uint64_t   inMetaOffset = readCertMetadata(inPath, inMeta, &signedCert);

  if (inMetaOffset == 0)
  {
    return false;
  }

  if (metadata.IsExpired())
  {
    std::wcout << L"[-] Khóa cha đã hết hạn, không thể dùng để ký!" << std::endl;
    return false;
  }

  if (signedCert)
  {
    std::wcout << L"[-] Tệp chứng chỉ đã được ký từ trước: " << inPath << std::endl;
    return false;
  }

  if (inMeta.type == 0x00)
  {
    std::wcout << L"[-] Bạn không thể ký khóa gốc!" << std::endl;
    return false;
  }
  if (metadata.type == 0x02)
  {
    if (inMeta.type == 0x01)
    {
      std::wcout << L"[-] Bạn không thể ký tệp khóa trung gian bằng khóa đầu cuối!" << std::endl;
      return false;
    } else if (inMeta.type == 0x02)
    {
      std::wcout << L"[-] Khóa đầu cuối không thể được ký bằng một khóa đầu cuối khác!" << std::endl;
      return false;
    }
  }

  // Ghi khóa cha vào tệp cần ký
  if (!File::Copy(inPath, outPath))
  {
    std::wcout << L"[-] Không thể sao chép tệp: " << inPath << " -> " << outPath << std::endl;
    return false;
  }

  // Băm tệp chứng chỉ cha để lấy mã băm
  std::vector<uint8_t> parentCertHashVec;
  if (!File::Hash(pubKeyPath, parentCertHashVec))
  {
    std::wcout << L"[-] Không thể băm tệp chứng chỉ cha: " << pubKeyPath << std::endl;
    return false;
  }

  // Khối định danh cha (64 byte) bao gồm: 32 byte Key ID + 32 byte Cert Hash
  std::vector<uint8_t> parentKeysData;
  parentKeysData.insert(parentKeysData.end(), metadata.currentKey, metadata.currentKey + 32);
  parentKeysData.insert(parentKeysData.end(), parentCertHashVec.begin(), parentCertHashVec.begin() + 32);

  if (!File::Write(outPath, parentKeysData, inMetaOffset))
  {
    std::wcout << L"[-] Không thể ghi khóa cha vào tệp: " << outPath << std::endl;
    return false;
  }

  // Băm tệp cần ký
  std::vector<uint8_t> certHash;
  if (!File::Hash(outPath, certHash))
  {
    std::wcout << L"[-] Không thể băm tệp: " << outPath << std::endl;
    return false;
  }

  // Đọc tệp khóa bí mật
  std::vector<uint8_t> secretKey;
  if (!File::Read(secKeyPath, secretKey))
  {
    std::wcout << L"[-] Không thể đọc tệp: " << secKeyPath << std::endl;
    return false;
  }

  // Tạo chữ ký cho tệp
  std::vector<uint8_t> signature(DILITHIUM_BYTES);
  size_t               signatureLength;
  Dilithium::sign(
      signature.data(), &signatureLength,
      certHash.data(), certHash.size(),
      secretKey.data());

  secureZeroize(secretKey.data(), secretKey.size());

  if (!File::Append(outPath, signature))
  {
    std::wcout << L"[-] Không thể thêm dữ liệu vào tệp: " << outPath << std::endl;
    return false;
  }

  std::wcout << L"[+] Ký thành công vào tệp chứng chỉ: " << outPath << std::endl;

  return true;
}

/**
 * Định dạng của tệp sau khi ký:
 * - Đối với khóa phân cấp:
 *     [2592 byte: Mảng khóa công khai]
 *     [x    byte: Khối siêu dữ liệu đã được chỉnh sửa]
 *     [4627 byte: Chữ ký]
 * - Đối với tệp mặc định (ký dữ liệu thông thường):
 *     [Nội dung tệp gốc]
 *     [32   byte: Mã băm của khóa dùng để ký (ID Khóa)]
 *     [4627 byte: Chữ ký Dilithium]
 */
static bool signDefaultFile(
    const std::wstring& secKeyPath,
    const std::wstring& pubKeyPath,
    const std::wstring& inPath,
    const std::wstring& outPath,
    const SignerMeta&   metadata)
{
  (void)pubKeyPath;

  if (metadata.IsExpired())
  {
    std::wcout << L"[-] Khóa ký đã hết hạn!" << std::endl;
    return false;
  }

  // Sao chép nội dung tệp gốc
  if (!File::Copy(inPath, outPath))
  {
    std::wcout << L"[-] Không thể sao chép tệp: " << inPath << " -> " << outPath << std::endl;
    return false;
  }

  // Băm tệp chứng chỉ của người ký
  std::vector<uint8_t> certHash;
  if (!File::Hash(pubKeyPath, certHash))
  {
    std::wcout << L"[-] Không thể băm tệp chứng chỉ ký: " << pubKeyPath << std::endl;
    return false;
  }

  // Khối siêu dữ liệu của tệp mặc định chứa ID khóa ký (32 byte) và Mã băm chứng chỉ (32 byte)
  std::vector<uint8_t> metaBytes;
  metaBytes.insert(metaBytes.end(), metadata.currentKey, metadata.currentKey + 32);
  metaBytes.insert(metaBytes.end(), certHash.begin(), certHash.begin() + 32);

  if (!File::Append(outPath, metaBytes))
  {
    std::wcout << L"[-] Không thể ghi siêu dữ liệu vào tệp: " << outPath << std::endl;
    return false;
  }

  // Băm toàn bộ nội dung tệp (bao gồm cả khối ID khóa ký vừa thêm)
  std::vector<uint8_t> fileHash;
  if (!File::Hash(outPath, fileHash))
  {
    std::wcout << L"[-] Không thể băm tệp: " << outPath << std::endl;
    return false;
  }

  // Đọc khóa bí mật
  std::vector<uint8_t> secretKey;
  if (!File::Read(secKeyPath, secretKey))
  {
    std::wcout << L"[-] Không thể đọc tệp: " << secKeyPath << std::endl;
    return false;
  }

  // Ký tệp
  std::vector<uint8_t> signature(DILITHIUM_BYTES);
  size_t               signatureLength;
  Dilithium::sign(
      signature.data(), &signatureLength,
      fileHash.data(), fileHash.size(),
      secretKey.data());

  secureZeroize(secretKey.data(), secretKey.size());

  // Nối chữ ký vào cuối tệp
  if (!File::Append(outPath, signature))
  {
    std::wcout << L"[-] Không thể thêm chữ ký vào tệp: " << outPath << std::endl;
    return false;
  }

  std::wcout << L"[+] Ký thành công tệp dữ liệu: " << outPath << std::endl;

  return true;
}

bool Sign::signFile(
    const std::wstring& secKeyPath,
    const std::wstring& pubKeyPath,
    const std::wstring& inPath,
    const std::wstring& outPath)
{
  SignerMeta metadata;
  uint64_t   metadataOffset = readCertMetadata(pubKeyPath, metadata);

  if (metadataOffset == 0)
  {
    std::wcout << L"[-] Tệp khóa cha không hợp lệ!" << std::endl;
    return false;
  }

  if (signType.compare(L"cert") == 0)
  {
    return signCertFile(
        secKeyPath, pubKeyPath,
        inPath, outPath, metadata);
  }

  return signDefaultFile(
      secKeyPath, pubKeyPath,
      inPath, outPath, metadata);
}

bool Sign::readMetadata(const std::wstring& pubKeyPath)
{
  SignerMeta metadata;
  bool       signedCert = false;
  uint64_t   offset     = readCertMetadata(pubKeyPath, metadata, &signedCert);

  if (offset == 0)
  {
    return false;
  }

  std::wcout << L"\n  ╔═════════════════════════════════════════════╗\n";
  std::wcout << L"  ║        THÔNG TIN CHỨNG CHỈ DILITHIUM        ║\n";
  std::wcout << L"  ╚═════════════════════════════════════════════╝\n";
  std::wcout << L"[+] Loại khóa    : ";
  if (metadata.type == 0x00)
    std::wcout << L"Khóa gốc (Root Key)" << std::endl;
  else if (metadata.type == 0x01)
    std::wcout << L"Khóa trung gian (Intermediate Key)" << std::endl;
  else if (metadata.type == 0x02)
    std::wcout << L"Khóa đầu cuối (End Key)" << std::endl;
  else
    std::wcout << L"Không xác định (0x" << std::hex << (int)metadata.type << std::dec << L")" << std::endl;

  std::wcout << L"[+] Trạng thái   : " << (signedCert ? L"Đã ký (Signed)" : L"Chưa ký (Self-signed/CSR)") << std::endl;
  std::wcout << L"[+] Tổ chức      : " << metadata.organization << std::endl;
  std::wcout << L"[+] Địa chỉ Email: " << metadata.email << std::endl;
  std::wcout << L"[+] Quốc gia     : " << metadata.country << std::endl;
  std::wcout << L"[+] Mô tả        : " << metadata.description << std::endl;
  std::wcout << L"[+] Ngày cấp     : " << SignerMeta::formatTime(metadata.issuedAt) << std::endl;
  std::wcout << L"[+] Ngày hết hạn : " << SignerMeta::formatTime(metadata.expiredAt);
  if (metadata.IsExpired())
    std::wcout << L" (Đã hết hạn - Expired)";
  std::wcout << std::endl;

  std::wcout << L"[+] Mã khóa hiện tại (SKI): ";
  for (int i = 0; i < 32; ++i)
    std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)metadata.currentKey[i];
  std::wcout << std::dec << std::setfill(L' ') << std::endl;

  std::wcout << L"[+] Mã khóa cha (AKI)     : ";
  bool hasParent = false;
  for (int i = 0; i < 32; ++i)
  {
    if (metadata.parentKey[i] != 0)
      hasParent = true;
  }
  if (hasParent)
  {
    for (int i = 0; i < 32; ++i)
      std::wcout << std::hex << std::setw(2) << std::setfill(L'0') << (int)metadata.parentKey[i];
    std::wcout << std::dec << std::setfill(L' ') << std::endl;
  } else
  {
    std::wcout << L"(Không có - Khóa gốc)" << std::endl;
  }
  std::wcout << std::endl;

  return true;
}

bool Sign::verifyFile(const std::wstring& pubKeyPath, const std::wstring& inPath)
{
  // Đọc siêu dữ liệu của tệp khóa công khai (chứng chỉ) để kiểm tra tính hợp lệ
  SignerMeta pubKeyMeta;
  if (readCertMetadata(pubKeyPath, pubKeyMeta) == 0)
  {
    std::wcout << L"[-] Tệp chứng chỉ không hợp lệ!" << std::endl;
    return false;
  }

  if (pubKeyMeta.IsExpired())
  {
    std::wcout << L"[-] Chứng chỉ dùng để xác thực đã HẾT HẠN!" << std::endl;
    return false;
  }

  // Đọc tệp chứng chỉ (dùng để xác minh chữ ký)
  std::vector<uint8_t> pubKeyData;
  if (!File::Read(pubKeyPath, pubKeyData))
  {
    std::wcout << L"[-] Không thể đọc tệp chứng chỉ: " << pubKeyPath << std::endl;
    return false;
  }

  if (pubKeyData.size() < DILITHIUM_PUBLICKEYBYTES)
  {
    std::wcout << L"[-] Tệp chứng chỉ không hợp lệ!" << std::endl;
    return false;
  }

  // Tính hash của public key để so sánh với signer ID nếu cần
  uint8_t pubKeyHash[32];
  Crypto::VNExos::sha256(pubKeyHash, pubKeyData.data(), DILITHIUM_PUBLICKEYBYTES);

  // Băm toàn bộ tệp chứng chỉ (để đối chiếu Cert Hash chống hạ cấp)
  std::vector<uint8_t> pubKeyFileHash;
  File::Hash(pubKeyPath, pubKeyFileHash);

  // Mở tệp cần xác minh
#if defined(_WIN32)
  std::ifstream inp(inPath, std::ios::in | std::ios::binary | std::ios::ate);
#else
  std::string   utf8FileName(inPath.begin(), inPath.end());
  std::ifstream inp(utf8FileName, std::ios::in | std::ios::binary | std::ios::ate);
#endif

  if (!inp)
  {
    std::wcout << L"[-] Không thể mở tệp cần xác minh: " << inPath << std::endl;
    return false;
  }

  std::streamsize fileSize = inp.tellg();
  if (fileSize < DILITHIUM_BYTES + 64)
  {
    std::wcout << L"[-] Tệp quá nhỏ, không thể chứa chữ ký hợp lệ!" << std::endl;
    return false;
  }

  // Đọc mã nhận diện (Magic Bytes) để phân biệt loại tệp
  uint64_t magic = 0;
  inp.seekg(fileSize - DILITHIUM_BYTES - 8, std::ios::beg);
  inp.read(reinterpret_cast<char*>(&magic), sizeof(magic));

  bool isCert = ((magic & ~(uint64_t)0xff) == 0x564e455051000000);

  // Đọc chữ ký ở cuối tệp
  std::vector<uint8_t> signature(DILITHIUM_BYTES);
  inp.seekg(fileSize - DILITHIUM_BYTES, std::ios::beg);
  inp.read(reinterpret_cast<char*>(signature.data()), DILITHIUM_BYTES);

  if (!isCert)
  {
    std::wcout << L"[*] Phân loại tệp: Tệp Dữ Liệu Thông Thường" << std::endl;
    // Đọc 64 byte (32 byte Key ID + 32 byte Cert Hash) ngay trước chữ ký
    std::vector<uint8_t> keyID(32);
    std::vector<uint8_t> certHash(32);
    inp.seekg(fileSize - DILITHIUM_BYTES - 64, std::ios::beg);
    inp.read(reinterpret_cast<char*>(keyID.data()), 32);
    inp.read(reinterpret_cast<char*>(certHash.data()), 32);

    // Kiểm tra Key ID có khớp với Public Key truyền vào không
    if (memcmp(keyID.data(), pubKeyHash, 32) != 0)
    {
      std::wcout << L"[!] CẢNH BÁO: Tệp này được ký bởi một chứng chỉ khác! (Key ID không khớp)." << std::endl;
      std::wcout << L"    Key ID trên tệp: ";
      dump(keyID.data(), 32);
      std::wcout << L"    Key ID của chứng chỉ cung cấp: ";
      dump(pubKeyHash, 32);
      std::wcout << L"[-] Từ chối xác thực. Vui lòng cung cấp đúng tệp chứng chỉ." << std::endl;
      return false;
    }

    // Kiểm tra Cert Hash chống hạ cấp
    if (memcmp(certHash.data(), pubKeyFileHash.data(), 32) != 0)
    {
      std::wcout << L"[!] LỖI BẢO MẬT: Tệp chứng chỉ không khớp hoàn toàn với chứng chỉ dùng để ký!" << std::endl;
      std::wcout << L"[-] Từ chối xác thực để ngăn chặn tấn công hạ cấp chứng chỉ." << std::endl;
      return false;
    }
  } else
  {
    std::wcout << L"[*] Phân loại tệp: Chứng Chỉ (Certificate)" << std::endl;
    SignerMeta inMeta;
    if (readCertMetadata(inPath, inMeta) != 0)
    {
      bool isRoot = true;
      for (int i = 0; i < 32; ++i)
      {
        if (inMeta.parentKey[i] != 0) isRoot = false;
      }

      if (!isRoot)
      {
        if (memcmp(inMeta.parentCertHash, pubKeyFileHash.data(), 32) != 0)
        {
          std::wcout << L"[!] LỖI BẢO MẬT: Tệp chứng chỉ cha không khớp hoàn toàn với chứng chỉ đã dùng để cấp phép!" << std::endl;
          std::wcout << L"[-] Từ chối xác thực để ngăn chặn tấn công hạ cấp chứng chỉ." << std::endl;
          return false;
        }
      }
    }
  }

  // Băm nội dung tệp (trừ phần chữ ký ở cuối)
  uint64_t signedDataSize = fileSize - DILITHIUM_BYTES;
  inp.seekg(0, std::ios::beg);

  Crypto::Keccak::State state;
  Crypto::Keccak::init(&state, 72);

  const size_t         BUFFER_SIZE = 64 * 1024;
  std::vector<uint8_t> buffer(BUFFER_SIZE);

  uint64_t remaining = signedDataSize;
  while (remaining > 0)
  {
    std::streamsize toRead = (remaining > static_cast<uint64_t>(BUFFER_SIZE)) ? BUFFER_SIZE : remaining;
    inp.read(reinterpret_cast<char*>(buffer.data()), toRead);
    std::streamsize bytesRead = inp.gcount();
    if (bytesRead == 0) break;

    Crypto::Keccak::absorb(&state, buffer.data(), bytesRead);
    remaining -= bytesRead;
  }

  std::vector<uint8_t> fileHash(128);
  Crypto::Keccak::finalize(&state, 0x25);
  Crypto::Keccak::squeeze(fileHash.data(), fileHash.size(), &state);

  inp.close();

  // Thực hiện xác thực bằng Dilithium
  if (!Dilithium::verify(signature.data(), signature.size(), fileHash.data(), fileHash.size(), pubKeyData.data()))
  {
    std::wcout << L"[-] XÁC THỰC THẤT BẠI: Chữ ký không hợp lệ hoặc dữ liệu đã bị sửa đổi!" << std::endl;
    return false;
  }

  std::wcout << L"[+] XÁC THỰC THÀNH CÔNG: Chữ ký hoàn toàn hợp lệ." << std::endl;
  return true;
}