/**
 * Copyright (c) 2026 VNExos
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
 * @param filePath    Đường dẫn của tệp
 * @param fileContent Nội dung của tệp
 * @param offset      Vị trí bắt đầu đọc tệp
 * @return false nếu có lỗi xãy ra trong quá trình ghi tệp
 */
bool Write(const std::wstring& filePath, const Content& fileContent, uint64_t offset = 0);

/**
 * Thêm một mảng byte vào cuối tệp.
 * @param filePath    Đường dẫn của tệp
 * @param fileContent Nội dung của tệp
 * @return false nếu có lỗi xãy ra trong quá trình thêm vào cuối tệp
 */
bool Append(const std::wstring& filePath, const Content& fileContent);

/**
 * Đọc nội dung của tệp vào một mảng byte.
 * @param filePath    Đường dẫn của tệp
 * @param fileContent Nội dung của tệp đã được đọc
 * @return false nếu có lỗi xãy ra trong quá trình đọc tệp
 */
bool Read(const std::wstring& filePath, Content& fileContent);

/**
 * Băm một tệp bằng thuật toán SHAV.
 * @param filePath    Đường dẫn của tệp
 * @param fileContent Nội dung của tệp đã được đọc
 * @param type        Phân loại thực toán SHAV
 * @return false nếu có lỗi xãy ra trong quá trình đọc tệp
 */
bool Hash(const std::wstring& filePath, std::vector<uint8_t>& outputHash, int type = 256);

/**
 * Sao chép tệp
 * @param inPath  Tệp đầu vào
 * @param outPath Tệp đầu ra
 * @return false nếu có lỗi xãy ra trong quá trình sao chép tệp
 */
bool Copy(const std::wstring& inPath, const std::wstring& outPath);
/**
 * Kiểm tra tệp tồn tại
 * @param path Tệp cần kiểm tra
 * @return true nếu tệp tồn tại, false thì ngược lại
 */
bool Exist(const std::wstring& path);
} // namespace File

#endif // __FILE_HPP
