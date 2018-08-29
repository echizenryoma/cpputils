//
// pch.h
// Header for standard system include files.
//

#pragma once

#define _SILENCE_TR1_NAMESPACE_DEPRECATION_WARNING

#include <gtest/gtest.h>
#include <string>
using namespace std;

#include "../libcrypto/type.h"

#define length(x) (sizeof(x)-1)

string bytes2str(const vector<byte>& bytes);

struct test
{
	const char* test_array;
	size_t test_array_size;
	long repeat_count;
	string result_array;
};
