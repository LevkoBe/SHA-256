cmake_minimum_required(VERSION 3.29)
project(SHA-256)

set(CMAKE_CXX_STANDARD 20)

add_executable(SHA-256
    main.cpp sha256.cpp TestSuite.h PrefixFinder.h sha256.h
)