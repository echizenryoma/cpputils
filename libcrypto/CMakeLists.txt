cmake_minimum_required(VERSION 3.10)

project(libcrypto)
set(SOURCE_FILES
        pch.h pch.cpp
        type.h

        base64.h base64.cpp
        hex.h hex.cpp

        hash.h hash.cpp
        hmac.h hmac.cpp
        pbkdf2.h pbkdf2.cpp

        des.h des.cpp
        aes.h aes.cpp
        rc4.h rc4.cpp
        blowfish.h blowfish.cpp

        rsa.h rsa.cpp
        dsa.h dsa.cpp
        ecdsa.h ecdsa.cpp

        padding.h
        iso10126padding.h iso10126padding.cpp
        nopadding.h nopadding.cpp
        oaepping.h oaepping.cpp
        pkcs1padding.h pkcs1padding.cpp
        pkcs5padding.h pkcs5padding.cpp
        pkcs7padding.h
        x932padding.h x932padding.cpp
        zeropadding.h zeropadding.cpp
)
add_library(${PROJECT_NAME} STATIC ${SOURCE_FILES})

find_package(CryptoPP REQUIRED)
find_package(OpenSSL REQUIRED)
message("OPENSSL_VERSION: ${OPENSSL_VERSION}")
message("OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
message("OPENSSL_CRYPTO_LIBRARY: ${OPENSSL_CRYPTO_LIBRARY}")
message("OPENSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} cryptopp-static OpenSSL::SSL OpenSSL::Crypto)

if (MSVC)
    add_definitions("/MP")
endif()
