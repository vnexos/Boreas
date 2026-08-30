# =========================================================
# Copyright (c) 2026 VNExos
#
# Được cấp phép theo Giấy phép GPLv3.
# Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
# =========================================================

# Tệp nhị phân đầu ra
TARGET = boreas

# Trình biên dịch
CC = clang
CXX = clang++
AS = clang

# Cờ biên dịch
CXXFLAGS = -Wall -Wextra -O2 -g -std=c++17 -Isrc

# Find all source files
SRCS_CPP := $(shell find . -type f -name "*.cpp")

# Convert to object files
OBJS := $(SRCS_CPP:.cpp=.o) \

# Default target
all: $(TARGET)

# Link
$(TARGET): $(OBJS)
	@echo "--> Đang liên kết $(TARGET)..."
	$(CXX) $(OBJS) -o $(TARGET)
	@echo "--> Xây thành công: $(TARGET)"

# Compile .cpp files (no PQC_DEFS needed, they use clean wrapper headers)
%.o: %.cpp
	@echo "--> Đang biên dịch C++: $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean
clean:
	@echo "--> Đang dọn dẹp..."
	rm -f $(OBJS) $(TARGET)
	@echo "--> Clean complete."

install: all
	@echo "--> Đang cài đặt..."
	mv $(TARGET) /usr/bin/$(TARGET)

.PHONY: all clean install