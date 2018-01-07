//
// pch.h
// Header for standard system include files.
//

#pragma once

#include <string>
using namespace std;

#include <gtest/gtest.h>

#include "../crypto/type.h"

#define length(x) (sizeof(x)-1)

string bytes2str(const vector<byte>& bytes)
{
	return string(bytes.begin(), bytes.end());
}

struct test_case
{
	const char* test_array;
	size_t test_array_size;
	long repeat_count;
	string result_array;
};
