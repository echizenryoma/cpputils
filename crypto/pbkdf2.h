/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"
#include <memory>
#include <cryptopp/pwdbased.h>

namespace crypto
{
	namespace mac
	{
		class PBKDF2;

		typedef PBKDF2 PBEwithHmac;

		using PasswordBasedKeyDerivationFunctionPtr = std::unique_ptr<CryptoPP::PasswordBasedKeyDerivationFunction>;
	}
}

class crypto::mac::PBKDF2
{
public:
	enum class HmacScheme
	{
		HmacMD2 = 2,
		HmacMD4 = 4,
		HmacMD5 = 5,

		HmacSHA1 = 1,
		HmacSHA224 = 224,
		HmacSHA256 = 256,
		HmacSHA384 = 384,
		HmacSHA512 = 512,

		HmacSHA3_224 = 3224,
		HmacSHA3_256 = 3256,
		HmacSHA3_384 = 3384,
		HmacSHA3_512 = 3512,
	};

private:
	static PasswordBasedKeyDerivationFunctionPtr GetPBEwithHmacFunction(HmacScheme hmac_scheme);
	static size_t GetHmacSize(HmacScheme hmac_scheme);
public:
	static vector<byte> derived(const vector<byte>& pwd, const vector<byte>& salt, uint32_t iterations, HmacScheme hmac_scheme = HmacScheme::HmacSHA1, size_t derived_size = 0);
};
