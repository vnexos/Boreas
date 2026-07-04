/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file main.cpp
 * @brief Tệp mã nguồn chính, điểm bắt đầu thực thi chương trình.
 */
#include "converter.hpp"
#include "crypto/randombytes.hpp"
#include "encrypt.hpp"
#include "sign.hpp"

#include <clocale>
#include <iomanip>
#include <iostream>
#include <random>
#include <string.h>
#include <string>
#include <vector>

using namespace Crypto;

// Hàm tiện ích để in mảng byte dạng Thập lục phân để dễ so sánh
void print_hex(const uint8_t* data, uint64_t len)
{
  uint64_t lines = len / 0x10 + 1;

  std::wcout << "\x1b[38;5;10m        ";
  for (uint8_t i = 0; i < 0x10; ++i)
    std::wcout << "  " << std::hex << std::setw(2) << std::setfill(L'0') << i;

  std::wcout << "\x1b[0m" << std::endl;

  uint64_t tmpIndex;
  for (uint64_t i = 0; i < lines; ++i)
  {
    std::wcout << L"\x1b[38;5;10m" << std::hex << std::setw(8) << std::setfill(L'0') << (int)i << L"\x1b[0m";
    for (uint64_t j = 0; j < 0x10 && (tmpIndex = i * 0x10 + j) < len; ++j)
    {
      std::wcout << "  " << std::setw(2) << std::setfill(L'0') << (int)data[tmpIndex];
    }
    std::wcout << "\x1b[0m" << std::endl;
  }
  std::wcout << std::endl
             << std::dec << std::setfill(L' ');
}

void printUsage(const char* prog)
{
  wprintf(L"\n");
  wprintf(L"  ╔═════════════════════════════════════════════╗\n");
  wprintf(L"  ║ VNExos Ám Băng                              ║\n");
  wprintf(L"  ║ ML-KEM-1024 (Kyber) + ML-DSA-87 (Dilithium) ║\n");
  wprintf(L"  ╚═════════════════════════════════════════════╝\n");
  wprintf(L"Sử dụng:\n");
  wprintf(L"[*] Mã hóa bất đối xứng: %s -encrypt\n", prog);
  wprintf(L"    -g <tệp khóa bí mật> <tệp khóa công khai>   : Sinh ra cặp khóa Kyber.\n");
  wprintf(L"    -e <tệp khóa công khai> <tệp vào> <tệp ra>  : Mã hóa tệp bằng khóa công khai\n");
  wprintf(L"                                                  Kyber kết hợp AES-256.\n");
  wprintf(L"    -d <tệp khóa bí mật> <tệp vào> <tệp ra>     : Giải mã tệp bằng khóa bí mật\n");
  wprintf(L"                                                  Kyber kết hợp AES-256.\n");
  wprintf(L"[*] Ký tệp:     %s -sign\n", prog);
  wprintf(L"    -g <tệp khóa bí mật> <tệp chứng chỉ>        : Sinh ra cặp khóa bí mật và chứng\n");
  wprintf(L"                                                  chỉ Dilithium.\n");
  wprintf(L"    -s <tệp khóa bí mật> <tệp chứng chỉ>        : Ký tệp bằng khóa bí mật và chứng\n");
  wprintf(L"       <tệp vào> <tệp ra>                         chỉ tương ứng.\n");
  wprintf(L"    -x <tệp chứng chỉ> <tệp vào>                : Xác minh tệp đã ký bằng thuật\n");
  wprintf(L"                                                  toán Dilithium.\n");
  wprintf(L"    -r <tệp chứng chỉ>                          : Đọc thông tin trong chứng chỉ.\n");
  wprintf(L"[+] Cờ bổ sung: \n");
  wprintf(L"    --verbose   [-v]                            : Xả ra mã Thập lục phân để dễ\n");
  wprintf(L"                                                  so sánh.\n");
  wprintf(L"    --type      [-t] <loại tệp>                 : Xác định loại tệp cần ký.\n");
  wprintf(L"                     elf                        : Chuyển đổi từ định dạng tệp\n");
  wprintf(L"                                                  nhị phân ELF sang định dạng\n");
  wprintf(L"                                                  VNEX và ký vào tệp.\n");
  wprintf(L"                     cert                       : Ký một chứng chỉ (bằng khóa bí\n");
  wprintf(L"                                                  mật của một chứng chỉ cấp cao\n");
  wprintf(L"                                                  hơn) để xác lập chuỗi tin cậy.\n");
  wprintf(L"                     (mặc định)                 : Ký vào cuối tệp.\n");
  wprintf(L"    --dilithium [-k] <loại khóa>                : Xác định loại khóa dilithium\n");
  wprintf(L"                                                  mà chương trình sẽ sinh ra.\n");
  wprintf(L"                     intermediate               : Sinh ra khóa trung gian - Khóa\n");
  wprintf(L"                                                  này dùng để ký các khóa đầu\n");
  wprintf(L"                                                  cuối.\n");
  wprintf(L"                     end-key                    : Sinh ra khóa đầu cuối - Khóa\n");
  wprintf(L"                                                  này sẽ dành cho các doanh\n");
  wprintf(L"                                                  nghiệp hoặc lập trình viên để\n");
  wprintf(L"                                                  ký các ứng dụng.\n");
  wprintf(L"                     (mặc định)                 : Sinh ra ra khóa gốc - Khóa này\n");
  wprintf(L"                                                  là khóa độc quyền của VNExos\n");
  wprintf(L"                                                  và sẽ không được tin cậy. CHỈ\n");
  wprintf(L"                                                  NÊN SINH KHÓA NÀY VỚI MỤC ĐÍCH\n");
  wprintf(L"                                                  NGHIÊN CỨU.\n");
  wprintf(L"[*] Mã hóa đối xứng: %s -aes256 <tệp vào> <tệp ra> <32 byte SHA3>\n", prog);
  wprintf(L"[*] Băm tệp: %s -shav <256|512|1024> -i <tên tệp|chuỗi byte>\n", prog);
}

bool         bDumpFlag = false;
std::wstring signType;
uint8_t      dilithiumKeyType = 0;

int main(int argc, char* argv[])
{
  // Cài đặt để chương trình có thể hoạt động tốt với tiếng Việt
  std::setlocale(LC_ALL, "C.UTF-8");
  if (argc < 2)
  {
    printUsage(argv[0]);
    return 1;
  }

  // Gieo hạt cho hàm tạo số ngẫu nhiên
  std::random_device rd;
  uint32_t           real_seed[8];
  for (int i = 0; i < 8; ++i)
  {
    real_seed[i] = rd();
  }
  randombytes_stir(reinterpret_cast<const uint8_t*>(real_seed), sizeof(real_seed));

  std::vector<std::wstring> cleanArgv;
  cleanArgv.push_back(Converter::Utf8ToWString(argv[0]));

  for (int i = 1; i < argc; ++i)
  {
    if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0)
      bDumpFlag = true;
    else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--type") == 0)
      signType = std::move(Converter::Utf8ToWString(argv[++i]));
    else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--dilithium") == 0)
    {
      const char* keyType = argv[++i];
      if (strcmp(keyType, "intermediate") == 0)
        dilithiumKeyType = 0x01;
      else if (strcmp(keyType, "end-key") == 0)
        dilithiumKeyType = 0x02;
      else
        dilithiumKeyType = 0x00;
    } else
      cleanArgv.push_back(Converter::Utf8ToWString(argv[i]));
  }

  if (cleanArgv.size() > 1)
  {
    if (cleanArgv[1].compare(L"-encrypt") == 0 && cleanArgv.size() >= 3) // Tập lệnh mã hóa
    {
      if (cleanArgv[2].compare(L"-g") == 0 && cleanArgv.size() == 5)     // Tạo cặp khóa
      {
        return !Encrypt::generateKey(cleanArgv[3], cleanArgv[4]);
      } else if (cleanArgv[2].compare(L"-e") == 0 && cleanArgv.size() == 6) // Mã hóa tệp
      {
        return !Encrypt::encryptFile(cleanArgv[3], cleanArgv[4], cleanArgv[5]);
      } else if (cleanArgv[2].compare(L"-d") == 0 && cleanArgv.size() == 6) // Giải mã tệp
      {
        return !Encrypt::decryptFile(cleanArgv[3], cleanArgv[4], cleanArgv[5]);
      } else
      {
        wprintf(L"[-] Lệnh sử dụng -encrypt không hợp lệ!\n");
        printUsage(argv[0]);
        return 1;
      }
    } else if (cleanArgv[1].compare(L"-sign") == 0 && cleanArgv.size() >= 3)
    {
      if (cleanArgv[2].compare(L"-g") == 0 && cleanArgv.size() == 5)
      {
        return !Sign::generateKey(cleanArgv[3], cleanArgv[4]);
      } else if (cleanArgv[2].compare(L"-s") == 0 && cleanArgv.size() == 7)
      {
        return !Sign::signFile(cleanArgv[3], cleanArgv[4], cleanArgv[5], cleanArgv[6]);
      } else if (cleanArgv[2].compare(L"-x") == 0 && cleanArgv.size() == 5)
      {
        return !Sign::verifyFile(cleanArgv[3], cleanArgv[4]);
      } else if (cleanArgv[2].compare(L"-r") == 0 && cleanArgv.size() == 4)
      {
        return !Sign::readMetadata(cleanArgv[3]);
      } else
      {
        wprintf(L"[-] Lệnh sử dụng -sign không hợp lệ!\n");
        printUsage(argv[0]);
        return 1;
      }
    } else if (cleanArgv[1].compare(L"-aes256") == 0)
    {
      if (cleanArgv.size() == 5)
      {
        return !Encrypt::aesEncrypt(cleanArgv[2], cleanArgv[3], cleanArgv[4]);
      } else
      {
        wprintf(L"[-] Lệnh sử dụng -aes256 không hợp lệ!\n");
        printUsage(argv[0]);
        return 1;
      }
    }
  }

  wprintf(L"[-] Không rõ lệnh hoặc sai số lượng tham số!");
  printUsage(argv[0]);
  return 0;
}