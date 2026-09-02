/**
 * Copyright (c) 2026 VNExos
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file encrypt.cpp
 * @brief Triển khai thuật toán mã hóa/giải mã cấp cao.
 */
#include "encrypt.hpp"
#include "converter.hpp"
#include "crypto/aes256.hpp"
#include "crypto/randombytes.hpp"
#include "file.hpp"
#include "kem/kyber.hpp"
#include "sig/dilithium.hpp"
#include "usx.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

extern bool         bDumpFlag;
extern std::wstring fileType;

void print_hex(const uint8_t* data, uint64_t len);

// Xóa sạch vùng nhớ nhạy cảm
inline void secureZeroize(void* p, size_t n)
{
  volatile uint8_t* vp = (volatile uint8_t*)p;
  while (n--)
    *vp++ = 0;
}

void dump(const uint8_t* data, const uint64_t len, const std::wstring label = std::wstring())
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

bool Encrypt::generateKey(const std::wstring& secKeyPath, const std::wstring& pubKeyPath)
{
  uint8_t pk[KYBER_INDCCA_PUBKEYBYTES];
  uint8_t sk[KYBER_INDCCA_SECKEYBYTES];

  wprintf(L"[+] Đang tạo cặp khóa mã hóa Kyber...\n");

  Kyber::generateKeyPair(pk, sk);

  if (!File::Write(pubKeyPath, File::Content(pk, pk + KYBER_INDCCA_PUBKEYBYTES)))
  {
    secureZeroize(sk, KYBER_INDCCA_SECKEYBYTES);
    return false;
  }
  if (!File::Write(secKeyPath, File::Content(sk, sk + KYBER_INDCCA_SECKEYBYTES)))
  {
    secureZeroize(sk, KYBER_INDCCA_SECKEYBYTES);
    return false;
  }

  std::wcout << L"[+] Khóa bí mật được lưu ở: " << secKeyPath << " (" << KYBER_INDCCA_SECKEYBYTES << " byte)\n";
  dump(sk, KYBER_INDCCA_SECKEYBYTES);
  std::wcout << L"[+] Khóa công khai được lưu ở: " << pubKeyPath << " (" << KYBER_INDCCA_PUBKEYBYTES << " byte)\n";
  dump(pk, KYBER_INDCCA_PUBKEYBYTES);

  secureZeroize(sk, KYBER_INDCCA_SECKEYBYTES);

  return true;
}

bool Encrypt::encryptFile(const std::wstring& pubKeyPath, const std::wstring& inPath, const std::wstring& outPath)
{
  // Đọc tệp chứa khóa công khai
  File::Content publicKey;
  if (!File::Read(pubKeyPath, publicKey))
    return false;

  if (publicKey.size() != KYBER_INDCCA_PUBKEYBYTES)
  {
    wprintf(L"[-] Khóa công khai không hợp lệ! (mong đợi %d byte nhưng có %zu byte)\n", KYBER_INDCCA_PUBKEYBYTES, publicKey.size());
    return false;
  }

  // Đọc tệp chứa dữ liệu thô cần mã hóa
  File::Content data;
  if (!File::Read(inPath, data))
    return false;

  // Cho phép dữ liệu rỗng nhưng phải có cảnh báo
  if (data.empty())
    wprintf(L"[!] Tệp chứa dữ liệu thô bị rỗng?\n");

  std::wcout << L"[+] Đang mã hóa " << inPath << " (" << data.size() << " byte)...\n";

  // Đóng gói bằng Kyber
  uint8_t ct[KYBER_INDCCA_CIPHERTEXTBYTES];
  uint8_t ss[KYBER_SSBYTES];

  Kyber::encapsulate(ct, ss, publicKey.data());

  // Tạo ra mảng khởi tạo (Initialization Vector) cho AES-CTR
  uint8_t iv[AES256_BLOCKLEN];
  Crypto::randombytes(iv, sizeof(iv));

  // Mã hóa AES-256-CTR
  Crypto::AES256::AES256Context aes;
  Crypto::AES256::init(&aes, ss);

  std::vector<uint8_t> ciphertext(data.size());
  if (!data.empty())
    Crypto::AES256::counter(&aes, iv, ciphertext.data(), data.data(), data.size());

  // Xóa sạch dữ liệu khóa AES
  secureZeroize(&aes, sizeof(aes));
  secureZeroize(ss, sizeof(ss));

  // Ghi vào tệp: [Bản mã Kyber][Mảng khởi tạo][Bản mã AES]
  File::Content payload;
  payload.reserve(sizeof(ct) + sizeof(iv) + ciphertext.size());

  payload.insert(payload.end(), ct, ct + sizeof(ct));
  payload.insert(payload.end(), iv, iv + sizeof(iv));

  if (!ciphertext.empty())
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

  // Lưu lại dữ liệu mã hóa
  if (!File::Write(outPath, payload))
    return false;

  std::wcout << L"[+] Đã lưu dữ liệu mã hóa vào: " << outPath << " (" << payload.size() << " byte)\n";
  dump(ct, sizeof(ct), L"Bản mã Kyber");
  dump(iv, sizeof(iv), L"Mảng khởi tạo");
  dump(ciphertext.data(), ciphertext.size(), L"Bản mã AES");

  return true;
}

bool Encrypt::decryptFile(const std::wstring& secKeyPath, const std::wstring& inPath, const std::wstring& outPath)
{
  // Đọc tệp chứa khóa bí mật
  File::Content secretKey;
  if (!File::Read(secKeyPath, secretKey))
    return false;

  if (secretKey.size() != KYBER_INDCCA_SECKEYBYTES)
  {
    wprintf(L"[-] Khóa bí mật không hợp lệ! (mong đợi %d byte nhưng có %zu byte)\n", KYBER_INDCCA_SECKEYBYTES, secretKey.size());
    secureZeroize(secretKey.data(), secretKey.size());
    return false;
  }

  // Đọc tệp chứa dữ liệu đã mã hóa
  File::Content encryptedData;
  if (!File::Read(inPath, encryptedData))
  {
    secureZeroize(secretKey.data(), secretKey.size());
    return false;
  }

  size_t headerSize = KYBER_INDCCA_CIPHERTEXTBYTES + AES256_BLOCKLEN;
  if (encryptedData.size() < headerSize)
  {
    wprintf(L"[-] Tệp mã hóa quá nhỏ! (tối thiểu %zu byte nhưng có %zu byte)\n", headerSize, encryptedData.size());
    secureZeroize(secretKey.data(), secretKey.size());
    return false;
  }

  std::wcout << L"[+] Đang giải mã " << inPath << " (" << encryptedData.size() << " byte)...\n";

  // Giải nén các thành phần của tệp mã hóa
  const uint8_t* ct     = encryptedData.data();
  const uint8_t* iv     = encryptedData.data() + KYBER_INDCCA_CIPHERTEXTBYTES;
  const uint8_t* aes    = encryptedData.data() + headerSize;
  size_t         aesLen = encryptedData.size() - headerSize;

  // Mở gói khóa Kyber
  uint8_t ss[KYBER_SSBYTES];
  Kyber::decapsulate(ss, ct, secretKey.data());

  // Xóa sạch khóa bí mật sau khi decapsulate xong
  secureZeroize(secretKey.data(), secretKey.size());

  // Giải mã AES-256-CTR
  Crypto::AES256::AES256Context context;
  Crypto::AES256::init(&context, ss);

  File::Content data(aesLen);
  if (aesLen > 0)
    Crypto::AES256::counter(&context, iv, data.data(), aes, aesLen);

  // Xóa sạch dữ liệu khóa AES
  secureZeroize(&context, sizeof(context));
  secureZeroize(ss, sizeof(ss));

  // Lưu lại dữ liệu giải mã
  if (!File::Write(outPath, data))
    return false;

  std::wcout << L"[+] Đã lưu dữ liệu giải mã vào: " << outPath << " (" << data.size() << " byte)\n";

  return true;
}

static std::vector<uint8_t> getKey(const std::wstring& key)
{
  std::string          charKey = Converter::WStringToUtf8(key);
  std::vector<uint8_t> result;

  if (charKey.length() & 1)
    return result;

  size_t length = charKey.length();
  result.reserve(length / 2);
  uint8_t elem = 0;
  for (uint64_t i = 0; i < length; i++)
  {
    elem   <<= 4;
    char c   = charKey[i];
    if (c >= '0' && c <= '9')
      elem |= c - '0';
    else if (c >= 'a' && c <= 'f')
      elem |= c - 87;
    else if (c >= 'A' && c <= 'F')
      elem |= c - 55;
    else
      return {};

    if (i & 1)
    {
      result.push_back(elem);
      elem = 0;
    }
  }

  return result;
}

static bool encryptDefaultFile(const std::wstring& inPath, const std::wstring& outPath, const std::wstring& key)
{
  std::vector<uint8_t> byteKey     = getKey(key);
  std::vector<uint8_t> magicNumber = {0, 0, 0, 'S', 'E', 'A', 'N', 'V'};

  if (byteKey.size() != 32)
  {
    std::wcout << L"[-] Mã khóa không hợp lệ: " << byteKey.size() << " byte (mong đợi: 32 byte)" << std::endl;
    return false;
  }

  std::vector<uint8_t> result;
  if (!File::Read(inPath, result))
  {
    std::wcout << L"[-] Không thể đọc tệp: " << inPath << std::endl;
    return false;
  }

  uint64_t i;
  for (i = 0; i < 8; ++i)
  {
    if (result[result.size() - 8 + i] != magicNumber[i])
      break;
  }

  if (i != 8)
  {
    Crypto::AES256::AES256Context context;
    Crypto::AES256::init(&context, byteKey.data());

    uint8_t iv[AES256_BLOCKLEN];

    Crypto::randombytes(iv, sizeof(iv));

    Crypto::AES256::counter(&context, iv, result.data(), result.data(), result.size());

    result.insert(result.end(), iv, iv + sizeof(iv));
    result.insert(result.end(), magicNumber.begin(), magicNumber.end());

    secureZeroize(&context, sizeof(context));
    secureZeroize(byteKey.data(), byteKey.size());

    if (!File::Write(outPath, result))
    {
      std::wcout << L"[-] Không thể ghi tệp: " << outPath << std::endl;
      return false;
    }

    std::wcout << L"[+] Mã hóa thành công vào tệp: " << outPath << std::endl;
  } else
  {
    Crypto::AES256::AES256Context context;
    Crypto::AES256::init(&context, byteKey.data());

    uint8_t iv[AES256_BLOCKLEN];

    for (uint64_t i = 0; i < AES256_BLOCKLEN; ++i)
    {
      iv[i] = result[result.size() - 24 + i];
    }

    result.resize(result.size() - 24);
    Crypto::AES256::counter(&context, iv, result.data(), result.data(), result.size());

    secureZeroize(&context, sizeof(context));
    secureZeroize(byteKey.data(), byteKey.size());
    secureZeroize(iv, sizeof(iv));

    if (!File::Write(outPath, result))
    {
      std::wcout << L"[-] Không thể ghi tệp: " << outPath << std::endl;
      return false;
    }

    secureZeroize(result.data(), result.size());

    std::wcout << L"[+] Giải mã thành công vào tệp: " << outPath << std::endl;
  }

  return true;
}

static bool encryptUSX(const std::wstring& inPath, const std::wstring& outPath, const std::wstring& key, USXHeader* header)
{
  // Kiểm tra các điều kiện để Mã hóa
  if (header->Flags & USX_HFLAG_ENCRYPTED)
  {
    std::wcout << L"[-] Tệp đã được mã hóa từ trước: " << inPath << std::endl;
    return false;
  }
  if (header->Flags & USX_HFLAG_SIGNED)
  {
    std::wcout << L"[-] Không thể mã hóa tệp đã ký: " << inPath << std::endl;
    return false;
  }

  // Lấy giá trị của khóa
  std::vector<uint8_t> aesKey = getKey(key);
  if (aesKey.size() != 32)
  {
    std::wcout << L"[-] Kích thước khóa AES không hợp lệ: " << key << std::endl;
    return false;
  }

  // Sao chép tệp
  if (!File::Copy(inPath, outPath))
  {
    std::wcout << L"[-] Không thể sao chép tệp: " << inPath << " -> " << outPath << std::endl;
    return false;
  }

  // Thay đổi bảng tiêu đề
  uint64_t size  = File::GetSize(outPath);
  header->Flags |= USX_HFLAG_ENCRYPTED | USX_HFLAG_HAS_KEM;
  if (!USX::putHeader(outPath, header))
  {
    return false;
  }

  // Thay đổi bảng bảo mật
  USXSecurity secTable;
  secTable.SignatureOffset = size;
  secTable.SignatureSize   = DILITHIUM_BYTES;
  secTable.KEMOffset       = secTable.SignatureOffset + ((secTable.SignatureSize + 7) & ~(uint64_t)7);
  secTable.KEMSize         = KYBER_INDCCA_CIPHERTEXTBYTES;
  if (!USX::putSecurityTable(outPath, &secTable))
    return false;

  // Thêm một vùng rỗng để chứa chữ ký
  File::Content zeroDilithium(secTable.KEMOffset - secTable.SignatureOffset);
  secureZeroize(zeroDilithium.data(), zeroDilithium.size());
  if (!File::Append(outPath, zeroDilithium))
  {
    std::wcout << L"[-] Không thể ghi tệp: " << outPath << std::endl;
    return false;
  }

  // Lấy tất cả các phân vùng
  std::vector<USXSection> sections;
  if (!USX::getSections(outPath, sections))
  {
    return false;
  }

  // Lọc phân vùng
  std::vector<uint64_t>   sectionBlockOffsets;
  std::vector<USXSection> filteredSections;
  for (auto& section : sections)
  {
    if (std::find(sectionBlockOffsets.begin(), sectionBlockOffsets.end(), section.BlockOffset) == sectionBlockOffsets.end())
    {
      filteredSections.push_back(section);
      sectionBlockOffsets.push_back(section.BlockOffset);
    }
  }

  // Khởi tạo phần mã hóa
  Crypto::AES256::AES256Context ctx;
  Crypto::AES256::init(&ctx, aesKey.data());

  // Mã hóa từng phân vùng
  for (auto& section : filteredSections)
  {
    if (section.Flags & USX_SFLAG_ZERO_INIT || section.BlockSize == 0)
      continue;
    File::Content rawSectionData;
    if (!File::Read(outPath, rawSectionData, section.BlockSize, section.BlockOffset))
    {
      std::wcout << L"[-] Không thể đọc phân vùng từ tệp: " << outPath << std::endl;
      return false;
    }

    std::vector<uint8_t> encryptedSection(rawSectionData.size());
    Crypto::AES256::counter(&ctx, section.InitializationVector, encryptedSection.data(), rawSectionData.data(), section.BlockSize);

    if (!File::Write(outPath, encryptedSection, section.BlockOffset))
    {
      std::wcout << L"[-] Không thể ghi phân vùng vào tệp: " << outPath << std::endl;
      return false;
    }
  }

  std::wcout << L"[+] Mã hóa USX thành công vào tệp: " << outPath << std::endl;

  return true;
}

bool Encrypt::aesEncrypt(const std::wstring& inPath, const std::wstring& outPath, const std::wstring& key)
{
  USXHeader header;
  if (USX::verifyHeader(inPath, &header))
    return encryptUSX(inPath, outPath, key, &header);
  return encryptDefaultFile(inPath, outPath, key);
}
