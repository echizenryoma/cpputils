cmake_minimum_required(VERSION 2.8)

project(cpputils)
set(CMAKE_CXX_STANDARD 11)
set(SOURCE_FILES aes.h aes.cpp base64.h des.h des.cpp hash.h hmac.h hex.h rsa.h rsa.cpp "test/test.cpp" "test/rsa_test.h")
add_executable(${PROJECT_NAME} ${SOURCE_FILES})

if(WIN32 AND MSVC)
	set(OPENSSL_USE_STATIC_LIBS TRUE)
	set(OPENSSL_MSVC_STATIC_RT TRUE)

#	set(MSVC_COMPILE_FLAGS
#			CMAKE_CXX_FLAGS
#			CMAKE_CXX_FLAGS_DEBUG
#			CMAKE_CXX_FLAGS_RELEASE
#			CMAKE_C_FLAGS
#			CMAKE_C_FLAGS_DEBUG
#			CMAKE_C_FLAGS_RELEASE)
#	foreach(FLAG ${MSVC_COMPILE_FLAGS})
#		string(REPLACE "/MD" "/MT" ${FLAG} "${${FLAG}}")
#	endforeach()
endif()

find_package(OpenSSL REQUIRED)

message("OPENSSL_VERSION: ${OPENSSL_VERSION}")
message("OPENSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")

if(WIN32 AND MSVC)	
	if(${CMAKE_SIZEOF_VOID_P} STREQUAL "8")
		set(_OPENSSL_ARCH_SUFFIX "64")
		set(_WINDOWS_ARCH_SUFFIX "x64")
	elseif(${CMAKE_SIZEOF_VOID_P} STREQUAL "4")
		set(_WINDOWS_ARCH_SUFFIX "x86")
	endif()

	include_directories("$ENV{OPENSSL_ROOT_DIR}/include${_OPENSSL_ARCH_SUFFIX}")
	message("OPENSSL_INCLUDE_DIR: $ENV{OPENSSL_ROOT_DIR}/include${_OPENSSL_ARCH_SUFFIX}")

	file(
		COPY 
			"$ENV{OPENSSL_ROOT_DIR}/lib/static/${_WINDOWS_ARCH_SUFFIX}/ossl_static.pdb" 
		DESTINATION
			"$ENV{OPENSSL_ROOT_DIR}/lib"
	)

	set(WINDOWS_SDK_LIBRARIES
		crypt32
		ws2_32
	)
	target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} ${WINDOWS_SDK_LIBRARIES})
else()
	include_directories(${OPENSSL_INCLUDE_DIR})
	message("OPENSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
	target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES})
endif()