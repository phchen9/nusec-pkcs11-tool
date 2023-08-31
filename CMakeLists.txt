cmake_minimum_required(VERSION 2.8)
project(nusec-pkcs11-tool)

SET(CMAKE_C_FLAGS "-Wall -Werror -Wno-pointer-sign -fno-signed-char -g -std=c99")


include_directories(include/pkcs11)
include_directories(src/common)

add_subdirectory(src/common)
add_subdirectory(src/derivation)
