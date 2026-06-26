# =========================================================
# Copyright (c) 2026 VNExos Inc.
#
# Được cấp phép theo Giấy phép GPLv3.
# Xem tệp LICENSE tại thư mục gốc để biết thêm chi tiết.
# =========================================================

# Tệp nhị phân đầu ra
TARGET = hlt.elf

# Trình biên dịch
CC = gcc
CXX = g++
AS = gcc

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
	@echo "--> Linking $(TARGET)..."
	$(CXX) $(OBJS) -o $(TARGET)
	@echo "--> Build successful: $(TARGET)"

# Compile .cpp files (no PQC_DEFS needed, they use clean wrapper headers)
%.o: %.cpp
	@echo "--> Compiling C++: $<"
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean
clean:
	@echo "--> Cleaning..."
	rm -f $(OBJS) $(TARGET)
	@echo "--> Clean complete."

.PHONY: all clean