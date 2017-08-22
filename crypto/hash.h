/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"

namespace crypto
{
	namespace message
	{
		namespace digest
		{
			class Hash;
		}
	}
}

class crypto::message::digest::Hash
{
public:
	enum HASH_SCHEME
	{
		MD4 = 4,
		MD5 = 5,
		SHA1 = 1,
		SHA224 = 224,
		SHA256 = 256,
		SHA384 = 384,
		SHA512 = 512
	};

	static vector<byte> digest(const vector<byte>& msg, const HASH_SCHEME& hash_scheme);
	static vector<byte> digest(const string& msg, const HASH_SCHEME& hash_scheme);
};