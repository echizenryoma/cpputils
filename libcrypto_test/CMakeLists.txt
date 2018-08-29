cmake_minimum_required(VERSION 3.10)

project(libcrypto_test)
set(SOURCE_FILES
        pch.h pch.cpp
        util.h
        
        test.cpp
        aes_test.cpp
        base64_test.cpp
        blowfish_test.cpp
        des_test.cpp
        dsa_test.cpp
        ecdsa_test.cpp
        hash_test.cpp
        hex_test.cpp
        hmac_test.cpp
        pbewithhmac_test.cpp   
        rc4_test.cpp
        rsa_test.cpp      
)
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

enable_testing()
find_package(GTest REQUIRED)
target_link_libraries(${PROJECT_NAME} libcrypto GTest::GTest GTest::Main)
add_test(${PROJECT_NAME} main)

if (MSVC)
    add_definitions("/MP")
endif()
