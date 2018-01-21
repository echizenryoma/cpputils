/*
* Copyright (c) 2012, 2018, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"

#include "padding.h"
using crypto::padding::Padding;
using crypto::padding::PaddingPtr;

#include <memory>
#include <openssl/pem.h>
using DSA_ptr = std::unique_ptr<DSA, decltype(&DSA_free)>;

namespace crypto
{
	namespace signature
	{
		class Dsa;
	}
}

class crypto::signature::Dsa
{
public:
	static DSA_ptr pubkey(const string& pem_key_str);
	static DSA_ptr privkey(const string& pem_key_str);

	static vector<byte> sign(const DSA_ptr& private_key, const vector<byte>& hash);
	static bool verify(const DSA_ptr& public_key, const vector<byte>& stext, const vector<byte>& hash);
};
