/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"
#include <memory>
#include <cryptopp/hmac.h>

namespace crypto
{
	namespace mac
	{
		class Hmac;
		using HMAC_BasePtr = std::unique_ptr<CryptoPP::HMAC_Base>;
	}
}

class crypto::mac::Hmac
{
public:
	enum class HashScheme
	{
		MD2 = 12,
		MD4 = 14,
		MD5 = 15,

		SHA1 = 1,

		SHA224 = 224,
		SHA256 = 256,
		SHA384 = 384,
		SHA512 = 512,

		SHA3_224 = 3224,
		SHA3_256 = 3256,
		SHA3_384 = 3384,
		SHA3_512 = 3512,
	};

private:
	static HMAC_BasePtr GetHmacFunction(HashScheme hash_scheme);
public:
	static vector<byte> mac(const vector<byte>& msg, const vector<byte>& key, HashScheme hash_scheme);
	static vector<byte> mac(const string& msg, const vector<byte>& key, HashScheme hash_scheme);
};
