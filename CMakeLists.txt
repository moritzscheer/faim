cmake_minimum_required(VERSION 3.16)
project(networking_http3 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Includes
include_directories(${CMAKE_SOURCE_DIR}/includes)
include_directories(${CMAKE_SOURCE_DIR}/src)

# External dependencies via pkg-config
find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBURING REQUIRED liburing)
pkg_check_modules(NGTCP2 REQUIRED libngtcp2)
pkg_check_modules(NGHTTP3 REQUIRED libnghttp3)

include_directories(
    ${LIBURING_INCLUDE_DIRS}
    ${NGTCP2_INCLUDE_DIRS}
    ${NGHTTP3_INCLUDE_DIRS}
)

link_directories(
    ${LIBURING_LIBRARY_DIRS}
    ${NGTCP2_LIBRARY_DIRS}
    ${NGHTTP3_LIBRARY_DIRS}
)

# Collect all project sources
file(GLOB_RECURSE SOURCES
    src/core/*.cpp
    src/middleware/http3/*.cpp
    src/middleware/quic/*.cpp
    src/middleware/*.cpp
    src/utils/*.cpp
    src/main.cpp
)

# Build executable
add_executable(${PROJECT_NAME} ${SOURCES})

# Link external libs
target_link_libraries(${PROJECT_NAME}
    ${LIBURING_LIBRARIES}
    ${NGTCP2_LIBRARIES}
    ${NGHTTP3_LIBRARIES}
)
