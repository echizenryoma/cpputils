/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
#include <cryptopp/config.h>
using std::vector;
using std::string;

class Hex
{
public:
	static string encode(const byte* message, const size_t& message_size, const bool &uppercase = true);
	static string encode(const vector<byte>& message, const bool &uppercase = true);
	static string encode(const string& message, const bool &uppercase = true);

	static vector<byte> decode(const string& encoded);
};
