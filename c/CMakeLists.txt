cmake_minimum_required(VERSION 3.11)
project(gm_test)

set(CMAKE_CXX_STANDARD 14)

add_executable(gm_test gm_test.c gm.c randombytes.c)