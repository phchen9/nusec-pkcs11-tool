cmake_minimum_required(VERSION 2.8)
project(ecdh)

find_library(softhsmpkcs11 STATIC)

add_executable(ecdh ecdh.c)
target_link_libraries(ecdh softhsmpkcs11)