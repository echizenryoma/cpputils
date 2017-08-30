//
// pch.h
// Header for standard system include files.
//

#pragma once

#include <gtest/gtest.h>
#include <cryptopp/config.h>
#include <string>
using std::string;
using std::vector;

string bytes2str(const vector<byte>& bytes);

struct test
{
	const char* test_array;
	size_t test_array_size;
	long repeat_count;
	string result_array;
};
