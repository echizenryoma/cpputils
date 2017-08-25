/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"
#include <cryptopp/filters.h>


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
	enum HashScheme
	{
		MD2 = 12,
		MD4 = 14,
		MD5 = 15,
		SHA1 = 1,
		SHA224 = 224,
		SHA256 = 256,
		SHA384 = 384,
		SHA512 = 512
	};

private:
	static CryptoPP::HashTransformation* GetHashFunction(HashScheme hash_scheme);
public:
	static vector<byte> digest(const vector<byte>& msg, HashScheme hash_scheme);
	static vector<byte> digest(const string& msg, HashScheme hash_scheme);
};
