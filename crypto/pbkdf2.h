/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"
#include <cryptopp/pwdbased.h>

namespace crypto
{
	namespace mac
	{
		class PBKDF2;

		typedef PBKDF2 PBEwithHmac;
	}
}

class crypto::mac::PBKDF2
{
public:
	enum HmacScheme
	{
		HmacMD2 = 2,
		HmacMD4 = 4,
		HmacMD5 = 5,

		HmacSHA = 1,
		HmacSHA1 = 1,
		HmacSHA224 = 224,
		HmacSHA256 = 256,
		HmacSHA384 = 384,
		HmacSHA512 = 512
	};

private:
	static CryptoPP::PasswordBasedKeyDerivationFunction* GetPBEwithHmacFunction(HmacScheme hmac_scheme);
	static size_t GetHmacSize(HmacScheme hmac_scheme);
public:
	static vector<byte> derived(const vector<byte>& pwd, const vector<byte>& salt, size_t iterations, HmacScheme hmac_scheme = HmacSHA1, size_t derived_size = 0);
};
