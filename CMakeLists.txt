cmake_minimum_required(VERSION 3.16)
project(BRYChallenge)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(${CMAKE_BINARY_DIR}/conan_toolchain.cmake)

file(GLOB_RECURSE data resources/*)

file(COPY ${data} DESTINATION resources)

find_package(OpenSSL REQUIRED)
find_package(Poco REQUIRED COMPONENTS Net)
find_package(GTest REQUIRED)

set(SOURCES
    src/main.cpp
    src/CMSApplication.cpp
    src/CMSSigner.cpp
    src/CMSVerifier.cpp
    src/FileHash.cpp
    src/RequestHandlerFactory.cpp
    src/handlers/SignHandler.cpp
    src/handlers/VerifyHandler.cpp
)

message(STATUS "Poco_INCLUDE_DIR: ${Poco_INCLUDE_DIR}")
include_directories(S{Poco_INCLUDE_DIR})

add_executable(app ${SOURCES})

target_include_directories(app PRIVATE ${CMAKE_BINARY_DIR} src)

target_link_libraries(app PRIVATE Poco::Poco OpenSSL::Crypto)

# Tests
include_directories(${GTest_INCLUDE_DIRS})

add_executable(FileHashTest test/FileHashTest.cpp src/FileHash.cpp)
add_executable(CMSSignerTest test/CMSSignerTest.cpp src/CMSSigner.cpp)
#add_executable(CMSVerifierTest test/CMSVerifierTest.cpp src/CMSVerifier.cpp)

target_include_directories(FileHashTest PRIVATE ${CMAKE_BINARY_DIR} GTest::gtest)
target_include_directories(CMSSignerTest PRIVATE ${CMAKE_BINARY_DIR} GTest::gtest)
#target_include_directories(CMSVerifierTest PRIVATE ${CMAKE_BINARY_DIR} GTest::gtest)

target_link_libraries(FileHashTest PUBLIC gtest::gtest OpenSSL::Crypto)
target_link_libraries(CMSSignerTest PUBLIC gtest::gtest OpenSSL::Crypto)
#target_link_libraries(CMSVerifierTest PUBLIC gtest::gtest OpenSSL::Crypto)

enable_testing()
add_test(NAME FileHashTest COMMAND FileHashTest)
add_test(NAME CMSSignerTest COMMAND CMSSignerTest)
#add_test(NAME CMSVerifierTest COMMAND CMSVerifierTest)
