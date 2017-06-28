cmake_minimum_required(VERSION 2.8)

project(cpputils)
set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES base64.h hash.h hmac.h hex.h rsa.h rsa.cpp test.cpp "test/rsa_test.h")
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

find_package(OpenSSL REQUIRED)

message("OPENSSL_VERSION: ${OPENSSL_VERSION}")
message("OPENSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")

if(WIN32 AND MSVC)	
	if(${CMAKE_SIZEOF_VOID_P} STREQUAL "8")
        set(_OPENSSL_ARCH_SUFFIX "64")
		set(_ARCH_SUFFIX "64")
	else()
		set(_ARCH_SUFFIX "32")
    endif()
	
	if(${CMAKE_CONFIGURATION_TYPES} STREQUAL "Debug")
		set(_TYPE_SUFFIX "d")
	endif()

	file(COPY "$ENV{OPENSSL_ROOT_DIR}\\bin${_OPENSSL_ARCH_SUFFIX}\\"
			DESTINATION "${CMAKE_BINARY_DIR}\\${CMAKE_CONFIGURATION_TYPES}\\"
			FILES_MATCHING PATTERN "*MD${_TYPE_SUFFIX}.dll")
	include_directories("$ENV{OPENSSL_ROOT_DIR}\\include${_OPENSSL_ARCH_SUFFIX}")
	message("OPENSSL_INCLUDE_DIR: $ENV{OPENSSL_ROOT_DIR}\\include${_OPENSSL_ARCH_SUFFIX}")
else()
	include_directories(${OPENSSL_INCLUDE_DIR})
	message("OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
endif()

target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
