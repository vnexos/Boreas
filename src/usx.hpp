/**
 * Copyright (c) 2026 VNExos
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file usx.hpp
 * @brief Định nghĩa cấu trúc cho Tệp thực thi bảo mật đa
 * kiến trúc (Universal Secured Executable - USX). Các phần
 * đệm trong cấu trúc là để dịch vị ví của các bảng đứng
 * liền sau thành các vị trí chẵn 8 nhằm tăng tốc độ tải các
 * phân vùng ra RAM (CPU hoạt động tốt nhất với các vị trí
 * chia hết cho 8)
 */
#ifndef __USX_H
#define __USX_H

#include <stdint.h>
#include <string>
#include <vector>

#define USX_MAGIC_0 'U'
#define USX_MAGIC_1 'S'
#define USX_MAGIC_2 'X'
#define USX_MAGIC_3 0x00

#define USX_VERSION_1_0 0x01               // Phiên bản định dạng USX 1.0
                                           // Loader phải reject nếu Version trong file > Version cao nhất mình hỗ trợ

#define USX_TYPE_EXECUTABLE     0x00       // Tệp thực thi
#define USX_TYPE_STATIC_LINKED  0x01       // Tệp liên kết tĩnh
#define USX_TYPE_DYNAMIC_LINKED 0x02       // Tệp liên kết động

#define USX_HFLAG_ENCRYPTED (1 << 0)       // Mã thô có mã hóa AES256-CTR
#define USX_HFLAG_SIGNED    (1 << 1)       // Có chữ ký số (Dilithium) trong USXSecurity
#define USX_HFLAG_HAS_KEM   (1 << 2)       // Có gói khóa KEM trong USXSecurity (mã hóa theo khóa công khai riêng máy/tài khoản)
#define USX_HFLAG_PIE       (1 << 3)       // Ảnh thực thi dạng độc lập vị trí (Điểm vào là vị trí tương đối, không phải địa chỉ tuyệt đối)

#define USX_ARCH_X86_64      0x0001        // Dòng Vi xử lý Intel, AMD 64-bit
#define USX_ARCH_AARCH64     0x0002        // Dòng Vi xử lý ARM 64-bit
#define USX_ARCH_RISCV64     0x0004        // Dòng Vi xử lý RISC-V 64-bit
#define USX_ARCH_RESERVED    0x0008        // Dành riêng cho Vi xử lý của Việt Nam sau này
#define USX_ARCH_X86         0x0010        // Dòng Vi xử lý Intel 32-bit
#define USX_ARCH_AARCH32     0x0020        // Dòng Vi xử lý ARM 32-bit
#define USX_ARCH_MIPS64      0x0040        // Dòng Vi xử lý MIPS 64-bit
#define USX_ARCH_MIPS32      0x0080        // Dòng Vi xử lý MIPS 32-bit
#define USX_ARCH_PPC64       0x0100        // Dòng Vi xử lý PowerPC 64-bit
#define USX_ARCH_SPARC64     0x0200        // Dòng Vi xử lý SPARC V9
#define USX_ARCH_S390X       0x0400        // Dòng Vi xử lý IBM System/390
#define USX_ARCH_LOONGARCH64 0x0800        // Dòng Vi xử lý LoongArch 64-bit
#define USX_ARCH_IA64        0x1000        // Dòng Vi xử lý Intel Itanium
#define USX_ARCH_AVR         0x2000        // Dòng Vi xử lý Atmel AVR
#define USX_ARCH_SUPERH      0x4000        // Dòng Vi xử lý SuperH (SH4)
#define USX_ARCH_OTHER       0x8000        // Dòng Vi xử lý Dị giáo (Custom/FPGA/VM)

#define USX_AFLAG_BIG_ENDIAN (1 << 0)      // Mã thô của Vi xử lý này là Big-endian (mặc định Little-endian nếu tắt)

#define USX_ARCHID_BITMASK_MASK 0x00007FFF // 15 bit thấp dùng cho các bit USX_ARCH_*
#define USX_ARCHID_SHIFT        15         // Số bit dịch để lấy ID khi ở chế độ ID riêng

#define USX_SFLAG_EXECUTABLE (1 << 0)      // Phân vùng có thể thực thi (code)
#define USX_SFLAG_WRITABLE   (1 << 1)      // Phân vùng có thể ghi (data), tắt = read-only (rodata)
#define USX_SFLAG_ENCRYPTED  (1 << 2)      // Phân vùng này có mã hóa riêng (dùng InitializationVector kèm theo)
#define USX_SFLAG_COMPRESSED (1 << 3)      // Phân vùng này có nén trước khi (mã hóa/ghi vào file)
#define USX_SFLAG_ZERO_INIT  (1 << 4)      // Phân vùng không lưu dữ liệu trong tệp, chỉ cấp phát & zero-init lúc load (kiểu .bss)
#define USX_SFLAG_TLS        (1 << 5)      // Phân vùng thuộc vùng Thread-Local Storage

#define USX_SYMBOL_FUNCTION 0x00           // Ký hiệu là một hàm
#define USX_SYMBOL_VARIABLE 0x01           // Ký hiệu là một biến/dữ liệu

#define __USX_STRUCT       struct __attribute__((packed))
#define __USX_STRINGIFY(x) #x
#define __USX_TOSTRING(x)  __USX_STRINGIFY(x)
#define __USX_STRIP(...)   __VA_ARGS__

typedef __USX_STRUCT
{
  /* NHẬN DIỆN VÀ KIỂM SOÁT (8 Byte) */
  uint8_t  MagicBytes[4]; // Bắt buộc phải là 'U', 'S', 'X', 0
  uint8_t  Version;       // Phiên bản của định dạng USX
  uint8_t  Type;          // Phân loại định dạng USX: 0-Tệp thực thi, 1-Tệp liên kết tĩnh, 2-Tệp liên kết động
  uint16_t TargetArch;    // Các nhân được hỗ trợ trong tệp thực thi này. Sử dụng các Bit trong danh sách USX_ARCH_

  /* THÔNG TIN CHUNG CỦA ỨNG DỤNG (8 Byte) */
  uint16_t AppVersionOffset; // Phiên bản của ứng dụng trong bảng chuỗi
  uint16_t AppVersionSize;   // Độ dài của phiên bản trong bảng chuỗi
  uint16_t Flags;            // Cờ điều khiển: Bit 0 = Mã hóa?, Bit 1 = Đã ký?, Bit 2 = Hỗ trợ đóng gói khóa, Bit 3 = Độc lập vị trí
  uint16_t HeaderSize;       // Kích thước của Tiêu đề (USXHeader)

  /* ĐIỂM VÀO (8 Byte) */
  uint64_t EntryPoint; // Điểm bắt đầu của chương trình trên RAM (Địa chỉ ảo)

  /* BẢNG KIẾN TRÚC VÀ BẢO MẬT (36 Byte) */
  uint64_t ArchTableOffset;   // Vị trí của Bảng kiến trúc Vi xử lý
  uint16_t ArchTableCount;    // Số lượng Vi xử lý mà tệp thực thi này hỗ trợ
  uint16_t ArchTableSize;     // Kích thước của Bảng kiến trúc
  uint64_t SecurityOffset;    // Vị trí của Bảng bảo mật
  uint32_t SecuritySize;      // Kích thước của Bảng bảo mật
  uint64_t StringTableOffset; // Vị trí của mảng chuỗi
  uint32_t StringTableSize;   // Kích thước của mảng chuỗi

  /* BẢO HIỂM VÀ PHẦN ĐỆM (4 Byte) */
  uint32_t HeaderCRC32; // Tổng kiểm của Tiêu đề
}
USXHeader;              // 64 Byte

typedef __USX_STRUCT
{
  /* CẤU HÌNH CHUNG CỦA VI XỬ LÝ */
  uint32_t ArchId;     // 17-bit phía sau sẽ dành cho các chip không thông dụng khác
                       // Các bit không thông dụng sẽ được biểu diễn dạng ID, không phải bit mask
  uint8_t Flags;       // Các cờ trạng thái cho riêng từng Vi xử lý
                       // Bit 0 = Big-endian?
  uint8_t Reserved[3]; // Khu vực đệm (để dành), bắt buộc là 0

  /* VỊ TRÍ CÁC BẢNG PHÂN VÙNG VÀ NHẬP/XUẤT */
  uint64_t SectionTableOffset; // Vị trí bắt đầu của bảng phân vùng
  uint16_t SectionTableCount;  // Số lượng bảng phân vùng
  uint16_t SectionTableSize;   // Kích thước bảng phân vùng
  uint64_t ExportTableOffset;  // Vị trí của bảng Xuất (Export)
  uint32_t ExportTableCount;   // Số lượng phần tử của bảng Xuất
  uint32_t ExportTableSize;    // Kích thước mỗi phần tử của bảng Xuất (byte)
  uint64_t ImportTableOffset;  // Vị trí của bảng Nhập (Import)
  uint32_t ImportTableCount;   // Số lượng phần tử của bảng Nhập
  uint32_t ImportTableSize;    // Kích thước mỗi phần tử của bảng Nhập (byte)

  /* PHẦN ĐỆM */
  uint32_t Reserved2; // Để dành 2, bắt buộc là 0
}
USXArch;              // 56 Byte

typedef __USX_STRUCT
{
  uint64_t SignatureOffset; // Vị trí của Chữ ký
  uint32_t SignatureSize;   // Kích thước của Chữ ký
  uint64_t KEMOffset;       // Vị trí của gói khóa
  uint32_t KEMSize;         // Kích thước của gói khóa
}
USXSecurity;                // 24 Byte

typedef __USX_STRUCT
{
  /* THÔNG TIN CHUNG CỦA PHÂN VÙNG */
  uint64_t NameOffset;  // Vị trí của Chuỗi trong mảng chuỗi
  uint32_t NameSize;    // Kích thước của chuỗi
  uint64_t BlockOffset; // Vị trí của khối phân vùng
  uint32_t BlockSize;   // Kích thước của khối phân vùng (byte)

  /* PHẦN HỖ TRỢ MÃ HÓA CHO CÁC PHÂN VÙNG */
  uint8_t InitializationVector[16]; // Mảng khởi tạo cho thuật toán AES256-CTR

  /* CÁC CỜ TRẠNG THÁI VÀ PHẦN ĐỆM */
  uint16_t Flags;       // Bit 0 = Có thể thực thi?, Bit 1 = Có thể ghi?
  uint8_t  Reserved[6]; // Để dành, bắt buộc là 0
}
USXSection;             // 48 Byte

typedef __USX_STRUCT
{
  uint64_t NameOffset;   // Vị trí của tên hàm/biến trong mảng chuỗi
  uint32_t NameSize;     // Kích thước của chuỗi
  uint64_t SymbolOffset; // Vị trí của hàm/biến trong khối
  uint8_t  SymbolType;   // 0 = Hàm, 1 = Biến/Dữ liệu
  uint8_t  Reserved[3];  // Để dành, bắt buộc là 0
}
USXExport;               // 24 Byte

typedef __USX_STRUCT
{
  uint64_t LibNameOffset;    // Vị trí của tên thư viện trong mảng chuỗi
  uint32_t LibNameSize;      // Kích thước của chuỗi
  uint64_t SymbolNameOffset; // Vị trí của tên hàm/biến cần nhập
  uint32_t SymbolNameSize;   // Kích thước của chuỗi
  uint64_t PatchOffset;      // Vị trí trong tệp này cần được vá
}
USXImport;                   // 32 Byte

#define __USX_USED_IMPORT_SECTION(_section) \
  __attribute__((used, section(".vnexos_usx_import" __USX_TOSTRING(_section))))
#define __USX_EXPORT_SECTION(_section) \
  __attribute__((section("." __USX_TOSTRING(_section) ".vnexos_usx_export")))

#define USX_EXPORT_FUNC __USX_EXPORT_SECTION(text)
#define USX_EXPORT_DATA __USX_EXPORT_SECTION(data)

// Hiện tại các hàm đa hình đã có thể được xuất nhưng chỉ nhập được vào
// duy nhất một hàm cùng tên trong chương trình. Nhưng vậy là vừa đủ cho
// môi trường Nhân lõi.
// TODO: Cách duy nhất là xây lại trình biên dịch C++ khác
#define USX_IMPORT(lib, ret, name, ...)                                                      \
  extern __attribute__((weak)) ret (*name)(__VA_ARGS__) __USX_USED_IMPORT_SECTION(.ptr) = 0; \
  __USX_USED_IMPORT_SECTION(.str)                                                            \
  static const char __usx_lib_##name[] = lib;                                                \
  _Pragma("GCC diagnostic push")                                                             \
      _Pragma("GCC diagnostic ignored \"-Wunused-parameter\"")                               \
          __USX_USED_IMPORT_SECTION(.sym)                                                    \
              __attribute__((weak))                                                          \
              ret                                                                            \
              __usx_sym_##name(__VA_ARGS__)                                                  \
  {                                                                                          \
    __builtin_trap();                                                                        \
  }                                                                                          \
  _Pragma("GCC diagnostic pop")

namespace USX {
USXHeader getHeader(const std::wstring& path);
/**
 * Hàm này sẽ tự động tính lại CRC32 của bảng tiêu đề
 */
bool putHeader(const std::wstring& path, USXHeader* header);

bool verifyHeader(const std::wstring& path, USXHeader* _header = nullptr);

USXSecurity getSecurityTable(const std::wstring& path);
bool        putSecurityTable(const std::wstring& path, const USXSecurity* security);

bool getSections(const std::wstring& path, std::vector<USXSection>& sections);
} // namespace USX

#endif // __USX_H
