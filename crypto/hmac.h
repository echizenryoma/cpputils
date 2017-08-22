/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"
#include <openssl/ossl_typ.h>

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

private:
	static const EVP_MD * GetHashFunction(const HASH_SCHEME& hash_scheme);
	static size_t GetMessageDigestLength(const HASH_SCHEME& hash_scheme);
public:
	static vector<byte> mac(const vector<byte>& msg, const vector<byte>& key, const HASH_SCHEME& hash_scheme);
	static vector<byte> mac(const string& msg, const vector<byte>& key, const HASH_SCHEME& hash_scheme);
};
