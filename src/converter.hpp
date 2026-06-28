/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file converter.hpp
 * @brief Khai báo các giao diện chuyển đổi chuỗi.
 */
#ifndef __CONVERTER_HPP
#define __CONVERTER_HPP

#include <string>

namespace Converter {

std::string  WStringToUtf8(const std::wstring& wstr);
std::wstring Utf8ToWString(const std::string& str);

} // namespace Converter

#endif // __CONVERTER_HPP
