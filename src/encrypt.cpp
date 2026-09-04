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
#include "utils.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

extern std::wstring fileType;

// Xóa sạch vùng nhớ nhạy cảm
inline void secureZeroize(void* p, size_t n)
{
  volatile uint8_t* vp = (volatile uint8_t*)p;
  while (n--)
    *vp++ = 0;
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
  std::wcout << L"[+] Khóa công khai được lưu ở: " << pubKeyPath << " (" << KYBER_INDCCA_PUBKEYBYTES << " byte)\n";
  dump(pk, KYBER_INDCCA_PUBKEYBYTES);

  secureZeroize(sk, KYBER_INDCCA_SECKEYBYTES);

  return true;
}

static bool encryptDefaultFileWithKEM(const std::wstring& pubKeyPath, const std::wstring& inPath, const std::wstring& outPath)
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

static bool encryptUSX(const std::wstring& inPath, const std::wstring& outPath, std::vector<uint8_t>& aesKey, USXHeader* header)
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
  if (aesKey.size() != 32)
  {
    std::wcout << L"[-] Kích thước khóa AES không hợp lệ!" << std::endl;
    return false;
  }

  if (bDumpFlag)
  {
    std::wcout << L"[*] Thông tin Tiêu đề USX (USXHeader):\n";
    std::wcout << L"    Phiên bản USX : " << static_cast<int>(header->Version) << L"\n";
    std::wcout << L"    Loại tệp      : " << static_cast<int>(header->Type) << L"\n";
    std::wcout << L"    Kiến trúc đích: 0x" << std::hex << header->TargetArch << std::dec << L"\n";
    std::wcout << L"    Cờ điều khiển : 0x" << std::hex << header->Flags << std::dec << L"\n";
    std::wcout << L"    Điểm vào RAM  : 0x" << std::hex << header->EntryPoint << std::dec << L"\n";
    std::wcout << L"    Số lượng Arch : " << header->ArchTableCount << L"\n";
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
  secTable.SignatureSize   = DILITHIUM_BYTES + 64;
  secTable.KEMOffset       = secTable.SignatureOffset + ((secTable.SignatureSize + 7) & ~(uint64_t)7);
  secTable.KEMSize         = KYBER_INDCCA_CIPHERTEXTBYTES;

  if (bDumpFlag)
  {
    std::wcout << L"[*] Cập nhật Bảng bảo mật (USXSecurity):\n";
    std::wcout << L"    Vị trí Chữ ký : 0x" << std::hex << secTable.SignatureOffset << L", Kích thước: " << std::dec << secTable.SignatureSize << L" byte\n";
    std::wcout << L"    Vị trí Gói KEM: 0x" << std::hex << secTable.KEMOffset << L", Kích thước: " << std::dec << secTable.KEMSize << L" byte\n";
    dump(reinterpret_cast<const uint8_t*>(&secTable), sizeof(USXSecurity), L"Bảng bảo mật thô (24 byte)");
  }

  if (!USX::putSecurityTable(outPath, &secTable))
    return false;

  // Thêm một vùng rỗng để chứa chữ ký
  File::Content zeroDilithium(secTable.KEMOffset - secTable.SignatureOffset, 0);
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

  if (bDumpFlag)
    std::wcout << L"[*] Tìm thấy " << sections.size() << L" phân vùng (" << filteredSections.size() << L" phân vùng độc lập để mã hóa)\n";

  // Khởi tạo phần mã hóa
  Crypto::AES256::AES256Context ctx;
  Crypto::AES256::init(&ctx, aesKey.data());

  // Mã hóa từng phân vùng
  for (size_t idx = 0; idx < filteredSections.size(); ++idx)
  {
    auto& section = filteredSections[idx];
    if (section.Flags & USX_SFLAG_ZERO_INIT || section.BlockSize == 0)
    {
      if (bDumpFlag)
        std::wcout << L"[*] Bỏ qua phân vùng ZERO_INIT/rỗng tại offset 0x" << std::hex << section.BlockOffset << std::dec << std::endl;
      continue;
    }
    File::Content rawSectionData;
    if (!File::Read(outPath, rawSectionData, section.BlockSize, section.BlockOffset))
    {
      std::wcout << L"[-] Không thể đọc phân vùng từ tệp: " << outPath << std::endl;
      secureZeroize(&ctx, sizeof(ctx));
      secureZeroize(aesKey.data(), aesKey.size());
      return false;
    }

    if (bDumpFlag)
    {
      std::wcout << L"[*] Đang mã hóa phân vùng [" << idx << L"] tại Offset 0x" << std::hex << section.BlockOffset
                 << L" (Kích thước: 0x" << section.BlockSize << L" byte)" << std::dec << std::endl;
      dump(section.InitializationVector, 16, L"Mảng khởi tạo (IV) phân vùng");
      dump(rawSectionData.data(), rawSectionData.size(), L"Dữ liệu phân vùng trước mã hóa");
    }

    std::vector<uint8_t> encryptedSection(rawSectionData.size());
    Crypto::AES256::counter(&ctx, section.InitializationVector, encryptedSection.data(), rawSectionData.data(), section.BlockSize);

    if (bDumpFlag)
      dump(encryptedSection.data(), encryptedSection.size(), L"Dữ liệu phân vùng sau mã hóa");

    if (!File::Write(outPath, encryptedSection, section.BlockOffset))
    {
      std::wcout << L"[-] Không thể ghi phân vùng vào tệp: " << outPath << std::endl;
      secureZeroize(&ctx, sizeof(ctx));
      secureZeroize(aesKey.data(), aesKey.size());
      return false;
    }
  }

  secureZeroize(&ctx, sizeof(ctx));
  secureZeroize(aesKey.data(), aesKey.size());

  return true;
}

static bool encryptUSXFileWithKEM(const std::wstring& pubKeyPath, const std::wstring& inPath, const std::wstring& outPath, USXHeader* header)
{
  // Đọc tệp khóa công khai
  File::Content pubKey;
  if (!File::Read(pubKeyPath, pubKey))
  {
    std::wcout << L"[-] Không thể đọc tệp khóa công khai: " << pubKeyPath << std::endl;
    return false;
  }

  // Tạo khóa công khai
  std::vector<uint8_t> ss(KYBER_SSBYTES);
  std::vector<uint8_t> ct(KYBER_INDCCA_CIPHERTEXTBYTES);
  Kyber::encapsulate(ct.data(), ss.data(), pubKey.data());

  // Mã hóa tệp USX
  if (!encryptUSX(inPath, outPath, ss, header))
  {
    secureZeroize(ss.data(), ss.size());
    return false;
  }

  if (!File::Append(outPath, ct))
  {
    std::wcout << L"[-] Không thể thêm gói khóa vào tệp USX: " << outPath << std::endl;
    return false;
  }

  std::wcout << L"[+] Đã mã hóa thành công vào tệp USX: " << outPath << std::endl;

  return true;
}

bool Encrypt::encryptFile(const std::wstring& pubKeyPath, const std::wstring& inPath, const std::wstring& outPath)
{
  USXHeader header;
  if (USX::verifyHeader(inPath, &header))
    return encryptUSXFileWithKEM(pubKeyPath, inPath, outPath, &header);
  return encryptDefaultFileWithKEM(pubKeyPath, inPath, outPath);
}

static bool decryptDefaultFileWithKEM(const std::wstring& secKeyPath, const std::wstring& inPath, const std::wstring& outPath)
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

  dump(ct, KYBER_INDCCA_CIPHERTEXTBYTES, L"Bản mã Kyber trích xuất");
  dump(iv, AES256_BLOCKLEN, L"Mảng khởi tạo (IV) trích xuất");

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

  dump(data.data(), data.size(), L"Dữ liệu sau khi giải mã");

  // Lưu lại dữ liệu giải mã
  if (!File::Write(outPath, data))
    return false;

  std::wcout << L"[+] Đã lưu dữ liệu giải mã vào: " << outPath << " (" << data.size() << " byte)\n";

  return true;
}

bool Encrypt::decryptFile(const std::wstring& secKeyPath, const std::wstring& inPath, const std::wstring& outPath)
{
  return decryptDefaultFileWithKEM(secKeyPath, inPath, outPath);
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

bool Encrypt::aesEncrypt(const std::wstring& inPath, const std::wstring& outPath, const std::wstring& key)
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
    dump(iv, sizeof(iv), L"Mảng khởi tạo (IV)");

    Crypto::AES256::counter(&context, iv, result.data(), result.data(), result.size());

    result.insert(result.end(), iv, iv + sizeof(iv));
    result.insert(result.end(), magicNumber.begin(), magicNumber.end());

    dump(result.data(), result.size(), L"Toàn bộ gói dữ liệu đã mã hóa");

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

    for (uint64_t j = 0; j < AES256_BLOCKLEN; ++j)
    {
      iv[j] = result[result.size() - 24 + j];
    }
    dump(iv, sizeof(iv), L"Mảng khởi tạo (IV) trích xuất");

    result.resize(result.size() - 24);
    Crypto::AES256::counter(&context, iv, result.data(), result.data(), result.size());

    dump(result.data(), result.size(), L"Dữ liệu sau khi giải mã");

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

bool Encrypt::encapsulateKey(const std::wstring& pubPath, const std::wstring& outPath)
{
  // Đọc khóa công khai
  File::Content pubData;
  if (!File::Read(pubPath, pubData))
  {
    std::wcout << L"Có lỗi xảy ra trong quá trình đọc tệp khóa công khai: " << pubPath << std::endl;
    return false;
  }

  // Đóng gói khóa
  std::vector<uint8_t> ciphertext(KYBER_INDCCA_CIPHERTEXTBYTES);
  std::vector<uint8_t> key(KYBER_SSBYTES);
  Kyber::encapsulate(ciphertext.data(), key.data(), pubData.data());

  for (uint64_t i = 0; i < key.size(); ++i)
    std::wcout << std::hex << std::setfill(L'0') << std::setw(2) << static_cast<int>(key[i]);
  std::wcout << std::dec << std::endl;

  secureZeroize(key.data(), key.size());
  secureZeroize(pubData.data(), pubData.size());

  if (!File::Write(outPath, ciphertext))
  {
    std::wcout << L"Có lỗi xảy ra trong quá trình ghi vào tệp: " << outPath << std::endl;
    return false;
  }

  return true;
}

bool Encrypt::decapsulateKey(const std::wstring& secPath, const std::wstring& kemPath)
{
  // Đọc khóa công khai
  File::Content secData;
  if (!File::Read(secPath, secData))
  {
    std::wcout << L"Có lỗi xảy ra trong quá trình đọc tệp khóa bí mật: " << secPath << std::endl;
    return false;
  }

  // Đọc gói khóa
  File::Content kemData;
  if (!File::Read(kemPath, kemData))
  {
    std::wcout << L"Có lỗi xảy ra trong quá trình đọc tệp gói khóa: " << secPath << std::endl;
    return false;
  }

  // Mở gói khóa
  std::vector<uint8_t> key(KYBER_SSBYTES);
  Kyber::decapsulate(key.data(), kemData.data(), secData.data());

  secureZeroize(secData.data(), secData.size());

  for (uint64_t i = 0; i < key.size(); ++i)
    std::wcout << std::hex << std::setfill(L'0') << std::setw(2) << static_cast<int>(key[i]);
  std::wcout << std::dec << std::endl;

  secureZeroize(key.data(), key.size());

  return true;
}
