cmake_minimum_required(VERSION 3.27)
project(crypto_2)

set(CMAKE_CXX_STANDARD 17)

add_executable(crypto_2 main.cpp
        AES_cryptography.cpp
        AES_cryptography.h
        matrix.cpp
        matrix.h
        file_crypt.cpp
        file_crypt.h
)
