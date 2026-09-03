/**
 * Copyright (c) 2026 VNExos
 *
 * Được cấp phép theo Giấy phép GPLv3.
 * Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
 *
 * @file utils.hpp
 * @brief Khai báo các tiện ích in ấn, hiển thị chi tiết (verbose/hexdump).
 */
#ifndef __UTILS_HPP
#define __UTILS_HPP

#include <cstdint>
#include <string>

extern bool bDumpFlag;

/**
 * In mảng byte dạng bảng thập lục phân (hex dump).
 * @param data Con trỏ tới mảng dữ liệu byte
 * @param len  Độ dài mảng byte
 */
void print_hex(const uint8_t* data, uint64_t len);

/**
 * In mảng byte dạng hexdump kèm theo nhãn nếu cờ verbose (bDumpFlag) được bật.
 * @param data  Con trỏ tới mảng dữ liệu byte
 * @param len   Độ dài mảng byte
 * @param label Nhãn mô tả dữ liệu
 */
void dump(const uint8_t* data, const uint64_t len, const std::wstring& label = std::wstring());

#endif // __UTILS_HPP
