/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>

namespace crypto
{
	namespace mac
	{
		class Hmac;
	}
}

class crypto::mac::Hmac
{
public:
	enum HashScheme
	{
		MD2 = 2,
		MD4 = 4,
		MD5 = 5,
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
	static CryptoPP::SimpleProxyFilter* GetFilter(EncodeScheme encode_scheme, CryptoPP::BufferedTransformation* const attachment);
	static CryptoPP::HMAC_Base* GetHmacFunction(HashScheme hash_scheme, const vector<byte>& key);
public:
	static vector<byte> mac(const vector<byte>& msg, const vector<byte>& key, HashScheme hash_scheme);
	static vector<byte> mac(const string& msg, const vector<byte>& key, HashScheme hash_scheme);

	static string mac(const vector<byte>& msg, const vector<byte>& key, HashScheme hash_scheme, EncodeScheme encode_scheme);
	static string mac(const string& msg, const vector<byte>& key, HashScheme hash_scheme, EncodeScheme encode_scheme);
};
