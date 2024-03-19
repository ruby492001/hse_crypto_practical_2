cmake_minimum_required(VERSION 3.27)
project(crypto_2)

set(CMAKE_CXX_STANDARD 17)

add_executable(crypto_2 main.cpp
        AES_256.cpp
        AES_256.h)
