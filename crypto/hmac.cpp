/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"

#include "hmac.h"
using crypto::mac::HMAC_BasePtr;

HMAC_BasePtr crypto::mac::Hmac::GetHmacFunction(HashScheme hash_scheme)
{
	switch (hash_scheme)
	{
	case HashScheme::MD2:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::Weak::MD2>>());
	case HashScheme::MD4:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::Weak::MD4>>());
	case HashScheme::MD5:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::Weak::MD5>>());
	case HashScheme::SHA1:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::SHA1>>());
	case HashScheme::SHA224:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::SHA224>>());
	case HashScheme::SHA256:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::SHA256>>());
	case HashScheme::SHA384:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::SHA384>>());
	case HashScheme::SHA512:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::SHA512>>());
	case HashScheme::SHA3_224:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::SHA3_224>>());
	case HashScheme::SHA3_256:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::SHA3_256>>());
	case HashScheme::SHA3_384:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::SHA3_384>>());
	case HashScheme::SHA3_512:
		return HMAC_BasePtr(std::make_unique<CryptoPP::HMAC<CryptoPP::SHA3_512>>());
	default:
		throw std::invalid_argument("[invalid_argument] <hmac.cpp> crypto::mac::Hmac::GetHmacFunction(HashScheme): {hash_scheme}  is not support.");
	}
}

vector<byte> crypto::mac::Hmac::mac(const vector<byte>& msg, const vector<byte>& key, HashScheme hash_scheme)
{
	return mac(string(msg.begin(), msg.end()), key, hash_scheme);
}

vector<byte> crypto::mac::Hmac::mac(const string& msg, const vector<byte>& key, HashScheme hash_scheme)
{
	string mac;
	HMAC_BasePtr hmac_function = GetHmacFunction(hash_scheme);
	hmac_function->SetKey(key.data(), key.size());
	CryptoPP::StringSource(msg, true, new CryptoPP::HashFilter(*hmac_function.get(), new CryptoPP::StringSink(mac)));
	return vector<byte>(mac.begin(), mac.end());
}
