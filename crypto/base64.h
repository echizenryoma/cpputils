/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
#include <cryptopp/config.h>
using std::vector;
using std::string;

class Base64
{
public:
	enum Mode
	{
		Standard = 4648,
		URL_Safe = 6920
	};

	static string encode(const byte* message, const size_t& messageSize, const Mode& mode = Standard, const bool& insertLineBreaks = false, const int& maxLineLength = 72);
	static string encode(const vector<byte>& message, const Mode& mode = Standard, const bool& insertLineBreaks = false, const int& maxLineLength = 72);
	static string encode(const string& message, const Mode& mode = Standard, const bool& insertLineBreaks = false, const int& maxLineLength = 72);

	static vector<byte> decode(const string& encoded, const Mode& mode = Standard);
};
