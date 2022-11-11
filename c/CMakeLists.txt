cmake_minimum_required(VERSION 3.10)
project(gm_test)

set(CMAKE_CXX_STANDARD 14)

add_executable(gm_test gm_test.c gm.c randombytes.c sm2.c sm3.c sm4.c)
