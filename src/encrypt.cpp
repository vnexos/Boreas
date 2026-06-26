/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file encrypt.cpp
 * @brief Triển khai logic mã hóa/giải mã cấp cao.
 */
#include "encrypt.hpp"
#include "crypto/aes256.hpp"
#include "crypto/randombytes.hpp"
#include "file.hpp"
#include "kem/kyber.hpp"
#include <iostream>
#include <string>

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

  wprintf(L"[+] Đang tạo cặp khóa mã hóa...\n");

  Kyber::generateKeyPair(pk, sk);

  if (!File::Write(pubKeyPath, File::Content(pk, pk + KYBER_INDCCA_PUBKEYBYTES)))
    return false;
  if (!File::Write(secKeyPath, File::Content(sk, sk + KYBER_INDCCA_SECKEYBYTES)))
    return false;

  std::wcout << L"[+] Khóa bí mật được lưu ở: " << secKeyPath << " (" << KYBER_INDCCA_SECKEYBYTES << " byte)\n";
  std::wcout << L"[+] Khóa công khai được lưu ở: " << pubKeyPath << " (" << KYBER_INDCCA_PUBKEYBYTES << " byte)\n";

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
    return false;
  }

  // Đọc tệp chứa dữ liệu đã mã hóa
  File::Content encryptedData;
  if (!File::Read(inPath, encryptedData))
    return false;

  size_t headerSize = KYBER_INDCCA_CIPHERTEXTBYTES + AES256_BLOCKLEN;
  if (encryptedData.size() < headerSize)
  {
    wprintf(L"[-] Tệp mã hóa quá nhỏ! (tối thiểu %zu byte nhưng có %zu byte)\n", headerSize, encryptedData.size());
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
