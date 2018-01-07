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
	enum HashScheme
	{
#ifndef OPENSSL_NO_MD2
		MD2 = 12,
#endif
#ifndef OPENSSL_NO_MD4
		MD4 = 14,
#endif
#ifndef OPENSSL_NO_MD5
		MD5 = 15,
#endif

#ifndef OPENSSL_NO_SHA0
		SHA1 = 1,
#endif
#ifndef OPENSSL_NO_SHA256
		SHA224 = 224,
		SHA256 = 256,
#endif
#ifndef OPENSSL_NO_SHA512
		SHA384 = 384,
		SHA512 = 512,
#endif
		/*
		 * SHA3_224 = 3224,
		 * SHA3_256 = 3256,
		 * SHA3_384 = 3384,
		 * SHA3_512 = 3512,
		 */		
	};
private:
public:
	static vector<byte> digest(const vector<byte>& msg, HashScheme hash_scheme);
	static vector<byte> digest(const string& msg, HashScheme hash_scheme);
};
