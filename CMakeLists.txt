cmake_minimum_required(VERSION 2.8)

project(cpputils)
set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES aes.h aes.cpp base64.h des.h des.cpp hash.h hmac.h hex.h rsa.h rsa.cpp "test/test.cpp" "test/rsa_test.h")
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

if(WIN32 AND MSVC)
	set(OPENSSL_USE_STATIC_LIBS TRUE)
	set(OPENSSL_MSVC_STATIC_RT TRUE)
endif()

find_package(OpenSSL REQUIRED)

message("OPENSSL_VERSION: ${OPENSSL_VERSION}")
message("OPENSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")

if(WIN32 AND MSVC)	
	if(${CMAKE_SIZEOF_VOID_P} STREQUAL "8")
		set(_OPENSSL_ARCH_SUFFIX "64")
	endif()	

	set(WINDOWS_SDK_LIBRARIES
		crypt32
		ws2_32
	)
	include_directories("$ENV{OPENSSL_ROOT_DIR}/include${_OPENSSL_ARCH_SUFFIX}")
	target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} ${WINDOWS_SDK_LIBRARIES})
else()
	include_directories(${OPENSSL_INCLUDE_DIR})
	target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
endif()