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

	enum EncodeScheme
	{
		Base64 = 64,
		Base64_NewLine_64 = 64064,
		Base64_NewLine_72 = 64072,
		Base64_NewLine_76 = 64076,

		Base64Url = 64100,

		Hex = 16,
		Hex_Uppercase = 1600,
		Hex_Lowercase = 1601
	};

private:
	static CryptoPP::SimpleProxyFilter* getFilter(EncodeScheme encode_scheme, CryptoPP::BufferedTransformation* const attachment);
	static CryptoPP::HashTransformation* getHashTransformation(HashScheme hash_scheme);
public:
	static vector<byte> digest(const vector<byte>& msg, HashScheme algorithm);
	static vector<byte> digest(const string& msg, HashScheme algorithm);

	static string digest(const vector<byte>& msg, HashScheme hash_scheme, EncodeScheme encode_scheme);
	static string digest(const string& msg, HashScheme hash_scheme, EncodeScheme encode_scheme);
};
