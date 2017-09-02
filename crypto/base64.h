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
	enum EncodeScheme
	{
		Standard = 4648,
		URL_Safe = 6920
	};

	static string encode(const vector<byte>& message, EncodeScheme encode_sheme = Standard, bool new_line = false, int per_line_length = 72);
	static string encode(const string& message, EncodeScheme encode_sheme = Standard, bool new_line = false, int per_line_length = 72);

	static vector<byte> decode(const string& encoded, EncodeScheme encode_sheme = Standard);
};
