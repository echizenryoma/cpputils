/*
* Copyright (c) 2012, 2018, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"

#include <memory>
#include <openssl/pem.h>
using EC_KEY_ptr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

namespace crypto
{
	namespace signature
	{
		class EcDsa;
	}
}

class crypto::signature::EcDsa
{
public:
	static EC_KEY_ptr pubkey(const string& pem_key_str);
	static EVP_KEY_ptr privkey(const string& pem_key_str);

	static vector<byte> sign(const EVP_KEY_ptr& private_key, const vector<byte>& hash);
	static bool verify(const EC_KEY_ptr& public_key, const vector<byte>& stext, const vector<byte>& hash);
};
