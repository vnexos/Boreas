/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file sign.hpp
 * @brief Khai báo các giao diện ký/xác thực tệp cấp cao.
 */
#ifndef __SIGN_HPP
#define __SIGN_HPP

#include <string>

namespace Sign {
/**
 * Tạo ra cặp khóa bí mật-công khai
 * @param secKeyPath đường dẫn tới tệp chứa khóa bí mật
 * @param pubKeyPath đường dẫn tới tệp chứa khóa công khai
 * @return false nếu xãy ra lỗi trong quá trình tạo khóa
 */
bool generateKey(const std::wstring& secKeyPath, const std::wstring& pubKeyPath);
/**
 * Ký tệp
 * @param secKeyPath đường dẫn tới khóa bí mật
 * @param inPath đường dẫn tới tệp cần ký
 * @param outPath đường dẫn tới tệp sau khi ký
 * @return false nếu xãy ra lỗi trong quá trình mã hóa
 */
bool signFile(const std::wstring& secKeyPath, const std::wstring& pubKeyPath, const std::wstring& inPath, const std::wstring& outPath);
/**
 * Xác thực tệp đã ký
 * @param pubKeyPath đường dẫn tới khóa bí mật
 * @param inPath đường dẫn tới tệp đã ký cần xác thực
 * @return false nếu xãy ra lỗi trong quá trình mã hóa
 */
bool verifyFile(const std::wstring& pubKeyPath, const std::wstring& inPath);
} // namespace Sign

#endif // __SIGN_HPP