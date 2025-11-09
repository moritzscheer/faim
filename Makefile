
# Compiler
CXX := g++

# Compiler Flags
CXXFLAGS := -std=c++20 -Wall -Wextra -O2 \
            -Iincludes \
						-Isrc \
            -I/usr/include/ngtcp2 \
						-I/usr/include/nghttp3 \
            -I/usr/include/liburing

# Linker flags
LDFLAGS := -lngtcp2 -lnghttp3 -luring -lpthread

# Precompiled header
PCH := build/pch.hpp.gch
PCH_HEADER := includes/pch.hpp

# Target binary
TARGET := faim

# Source and build directories
SRC_DIR := src
BUILD_DIR := build

# Find all .cpp files
SRCS := $(shell find $(SRC_DIR) -name '*.cpp')
OBJS := $(SRCS:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

# Default rule
all: $(PCH) $(TARGET)

# Precompile headers
$(PCH): $(PCH_HEADER)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -x c++-header $< -o $@

# Link binary
$(TARGET): $(OBJS)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

# Compile each .cpp into .o using PCH
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp $(PCH)
	@mkdir -p $(dir $@)
	$(CXX) $(CXXFLAGS) -include $(PCH_HEADER) -c $< -o $@

# Clean everything
clean:
	rm -rf $(BUILD_DIR) $(TARGET)

.PHONY: all clean
