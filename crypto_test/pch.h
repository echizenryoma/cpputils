//
// pch.h
// Header for standard system include files.
//

#pragma once

#define _SILENCE_TR1_NAMESPACE_DEPRECATION_WARNING

#include <string>
using namespace std;

#include <gtest/gtest.h>

#include "../crypto/type.h"

struct test_case
{
	const char* test_array;
	size_t test_array_size;
	long repeat_count;
	string result_array;
};

string bytes2str(const vector<byte>&);