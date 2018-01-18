/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "pbkdf2.h"
using crypto::mac::PasswordBasedKeyDerivationFunctionPtr;

PasswordBasedKeyDerivationFunctionPtr crypto::mac::PBKDF2::GetPBEwithHmacFunction(HmacScheme hmac_scheme)
{
	switch (hmac_scheme)
	{
	case HmacScheme::HmacMD2:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::Weak::MD2>>());
	case HmacScheme::HmacMD4:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::Weak::MD4>>());
	case HmacScheme::HmacMD5:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::Weak::MD5>>());
	case HmacScheme::HmacSHA1:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA1>>());
	case HmacScheme::HmacSHA224:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA224>>());
	case HmacScheme::HmacSHA256:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256>>());
	case HmacScheme::HmacSHA384:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA384>>());
	case HmacScheme::HmacSHA512:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512>>());
	case HmacScheme::HmacSHA3_224:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_224>>());
	case HmacScheme::HmacSHA3_256:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_256>>());
	case HmacScheme::HmacSHA3_384:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_384>>());
	case HmacScheme::HmacSHA3_512:
		return PasswordBasedKeyDerivationFunctionPtr(std::make_unique<CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA3_512>>());
	default:
		throw std::invalid_argument("[invalid_argument] <pdkdf2.cpp> crypto::mac::PBKDF2::GetPBEwithHmacFunction(HmacScheme hmac_scheme): {hmac_scheme} is not support.");
	}
}

size_t crypto::mac::PBKDF2::GetHmacSize(HmacScheme hmac_scheme)
{
	switch (hmac_scheme)
	{
	case HmacScheme::HmacMD2:
		return CryptoPP::Weak::MD2::DIGESTSIZE;
	case HmacScheme::HmacMD4:
		return CryptoPP::Weak::MD4::DIGESTSIZE;
	case HmacScheme::HmacMD5:
		return CryptoPP::Weak::MD5::DIGESTSIZE;
	case HmacScheme::HmacSHA1:
		return CryptoPP::SHA1::DIGESTSIZE;
	case HmacScheme::HmacSHA224:
		return CryptoPP::SHA224::DIGESTSIZE;
	case HmacScheme::HmacSHA256:
		return CryptoPP::SHA256::DIGESTSIZE;
	case HmacScheme::HmacSHA384:
		return CryptoPP::SHA384::DIGESTSIZE;
	case HmacScheme::HmacSHA512:
		return CryptoPP::SHA512::DIGESTSIZE;
	case HmacScheme::HmacSHA3_224:
		return CryptoPP::SHA3_224::DIGESTSIZE;
	case HmacScheme::HmacSHA3_256:
		return CryptoPP::SHA3_256::DIGESTSIZE;
	case HmacScheme::HmacSHA3_384:
		return CryptoPP::SHA3_384::DIGESTSIZE;
	case HmacScheme::HmacSHA3_512:
		return CryptoPP::SHA3_512::DIGESTSIZE;
	default:
		throw std::invalid_argument("[invalid_argument] <pdkdf2.cpp> crypto::mac::PBKDF2::GetPBEwithHmacFunction(HmacScheme hmac_scheme): {hmac_scheme} is not support.");
	}
}

vector<byte> crypto::mac::PBKDF2::derived(const vector<byte>& pwd, const vector<byte>& salt, uint32_t iterations, HmacScheme hmac_scheme, size_t derived_size)
{
	if (derived_size == 0)
	{
		derived_size = GetHmacSize(hmac_scheme);
	}

	string mac;
	vector<byte> derived(derived_size);
	PasswordBasedKeyDerivationFunctionPtr peb_with_hmac_function = GetPBEwithHmacFunction(hmac_scheme);
	peb_with_hmac_function.get()->DeriveKey(
		derived.data(), derived.size(),
		0,
		pwd.data(), pwd.size(),
		salt.data(), salt.size(),
		iterations
	);
	return derived;
}
