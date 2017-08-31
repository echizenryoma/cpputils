/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"

namespace crypto
{
	namespace encode
	{
		class Hex;
		typedef Hex Base16;
	}
}

class crypto::encode::Hex
{
public:
	static string encode(const vector<byte>& msg, const bool& uppercase = true);
	static string encode(const string& msg, const bool& uppercase = true);

	static vector<byte> decode(const string& etext);
};
