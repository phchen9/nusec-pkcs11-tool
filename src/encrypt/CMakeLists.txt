cmake_minimum_required(VERSION 2.8)
project(encrypt)

find_library(softhsmpkcs11 STATIC)

add_executable(aes_ecb aes_ecb.c)
add_executable(aes_cbc aes_cbc.c)

target_link_libraries(aes_ecb softhsmpkcs11)
target_link_libraries(aes_cbc softhsmpkcs11)