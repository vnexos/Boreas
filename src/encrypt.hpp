/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file encrypt.hpp
 * @brief Khai báo các giao diện mã hóa/giải mã cấp cao.
 */
#ifndef __ENCRYPT_HPP
#define __ENCRYPT_HPP

#include <string>

namespace Encrypt {
/**
 * Tạo ra cặp khóa bí mật-công khai
 * @param secKeyPath đường dẫn tới tệp chứa khóa bí mật
 * @param pubKeyPath đường dẫn tới tệp chứa khóa công khai
 * @return false nếu xãy ra lỗi trong quá trình tạo khóa
 */
bool generateKey(const std::wstring& secKeyPath, const std::wstring& pubKeyPath);
/**
 * Mã hóa tệp
 * @param pubKeyPath đường dẫn tới khóa công khai
 * @param inPath đường dẫn tới tệp cần mã hóa
 * @param outPath đường dẫn tới tệp lưu dữ liệu mã hóa
 * @return false nếu xãy ra lỗi trong quá trình mã hóa
 */
bool encryptFile(const std::wstring& pubKeyPath, const std::wstring& inPath, const std::wstring& outPath);
/**
 * Giải mã tệp
 * @param secKeyPath đường dẫn tới khóa bí mật
 * @param inPath đường dẫn tới tệp cần giải mã
 * @param outPath đường dẫn tới tệp lưu dữ liệu sau khi giải mã
 * @return false nếu xãy ra lỗi trong quá trình giải mã
 */
bool decryptFile(const std::wstring& secKeyPath, const std::wstring& inPath, const std::wstring& outPath);
} // namespace Encrypt

#endif // __ENCRYPT_HPP
