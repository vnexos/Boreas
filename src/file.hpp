/**
 * Copyright (c) 2026 VNExos Inc.
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file file.hpp
 * @brief Khai báo các tiện ích thao tác xử lý tệp tin.
 */
#ifndef __FILE_HPP
#define __FILE_HPP

#include <stdint.h>
#include <string>
#include <vector>

namespace File {

/* Nội dung của tệp là một mảng của các byte */
using Content = std::vector<uint8_t>;

/**
 * Viết nội dung là một mảng byte vào tệp.
 * @param fileName    Tên của tệp
 * @param fileContent Nội dung của tệp
 * @return false nếu có lỗi xãy ra trong quá trình ghi tệp
 */
bool Write(const std::wstring& fileName, const Content& fileContent);

/**
 * Đọc nội dung của tệp vào một mảng byte.
 * @param fileName Tên của tệp
 * @param fileContent Nội dung của tệp đã được đọc
 * @return false nếu có lỗi xãy ra trong quá trình đọc tệp
 */
bool Read(const std::wstring& fileName, Content& fileContent);

} // namespace File

#endif // __FILE_HPP
