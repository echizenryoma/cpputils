/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "hmac.h"
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>

CryptoPP::HMAC_Base* crypto::mac::Hmac::GetHmacFunction(HashScheme hash_scheme)
{
	switch (hash_scheme)
	{
	case MD2:
		return new CryptoPP::HMAC<CryptoPP::Weak::MD2>();
	case MD4:
		return new CryptoPP::HMAC<CryptoPP::Weak::MD4>();
	case MD5:
		return new CryptoPP::HMAC<CryptoPP::Weak::MD5>();
	case SHA1:
		return new CryptoPP::HMAC<CryptoPP::SHA1>();
	case SHA224:
		return new CryptoPP::HMAC<CryptoPP::SHA224>();
	case SHA256:
		return new CryptoPP::HMAC<CryptoPP::SHA256>();
	case SHA384:
		return new CryptoPP::HMAC<CryptoPP::SHA384>();
	case SHA512:
		return new CryptoPP::HMAC<CryptoPP::SHA512>();
	case SHA3_224:
		return new CryptoPP::HMAC<CryptoPP::SHA3_224>();
	case SHA3_256:
		return new CryptoPP::HMAC<CryptoPP::SHA3_256>();
	case SHA3_384:
		return new CryptoPP::HMAC<CryptoPP::SHA3_384>();
	case SHA3_512:
		return new CryptoPP::HMAC<CryptoPP::SHA3_512>();
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
	CryptoPP::HMAC_Base* hmac_function = GetHmacFunction(hash_scheme);
	hmac_function->SetKey(key.data(), key.size());
	CryptoPP::StringSource(msg, true, new CryptoPP::HashFilter(*hmac_function, new CryptoPP::StringSink(mac)));
	delete hmac_function;
	return vector<byte>(mac.begin(), mac.end());
}
