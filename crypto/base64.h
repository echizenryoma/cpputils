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
		class Base64;
	}
}


class crypto::encode::Base64
{
public:
	static string encode(const byte* msg, size_t msg_size);
	static string encode(const vector<byte>& msg);
	static string encode(const string& msg);

	static vector<byte> decode(const string& encoded);
};
