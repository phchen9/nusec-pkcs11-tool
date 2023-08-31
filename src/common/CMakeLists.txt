cmake_minimum_required(VERSION 2.8)
project(softhsmpkcs11)

add_library(softhsmpkcs11 common.c pkcs11.c gopt.c common.h gopt.h)

target_link_libraries(softhsmpkcs11 dl)
