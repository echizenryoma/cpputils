/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"

#include "hash.h"

CryptoPP::HashTransformation* crypto::message::digest::Hash::GetHashFunction(HashScheme hash_scheme)
{
	switch (hash_scheme)
	{
	case HashScheme::MD2:
		return new CryptoPP::Weak::MD2();
	case HashScheme::MD4:
		return new CryptoPP::Weak::MD4();
	case HashScheme::MD5:
		return new CryptoPP::Weak::MD5();
	case HashScheme::SHA1:
		return new CryptoPP::SHA();
	case HashScheme::SHA224:
		return new CryptoPP::SHA224();
	case HashScheme::SHA256:
		return new CryptoPP::SHA256();
	case HashScheme::SHA384:
		return new CryptoPP::SHA384();
	case HashScheme::SHA512:
		return new CryptoPP::SHA512();
	case HashScheme::SHA3_224:
		return new CryptoPP::SHA3_224();
	case HashScheme::SHA3_256:
		return new CryptoPP::SHA3_256();
	case HashScheme::SHA3_384:
		return new CryptoPP::SHA3_384();
	case HashScheme::SHA3_512:
		return new CryptoPP::SHA3_512();
	default:
		throw std::invalid_argument("[invalid_argument] <hash.cpp> crypto::message::digest::Hash::GetHashFunction(HashScheme): {hash_scheme}.");
	}
}

vector<byte> crypto::message::digest::Hash::digest(const vector<byte>& msg, HashScheme hash_scheme)
{
	return digest(string(msg.begin(), msg.end()), hash_scheme);
}

vector<byte> crypto::message::digest::Hash::digest(const string& msg, HashScheme hash_scheme)
{
	string digest;

	CryptoPP::HashTransformation* hash = GetHashFunction(hash_scheme);
	CryptoPP::StringSource(msg, true, new CryptoPP::HashFilter(*hash, new CryptoPP::StringSink(digest)));

	delete hash;
	return vector<byte>(digest.begin(), digest.end());
}
