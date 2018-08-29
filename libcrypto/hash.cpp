/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"

#include "hash.h"

using crypto::message::digest::HashTransformationPtr;

HashTransformationPtr crypto::message::digest::Hash::GetHashFunction(HashScheme hash_scheme)
{
	switch (hash_scheme)
	{
	case HashScheme::MD2:
		return HashTransformationPtr(std::make_unique<CryptoPP::Weak::MD2>());
	case HashScheme::MD4:
		return HashTransformationPtr(std::make_unique<CryptoPP::Weak::MD4>());
	case HashScheme::MD5:
		return HashTransformationPtr(std::make_unique<CryptoPP::Weak::MD5>());
	case HashScheme::SHA1:
		return HashTransformationPtr(std::make_unique<CryptoPP::SHA1>());
	case HashScheme::SHA224:
		return HashTransformationPtr(std::make_unique<CryptoPP::SHA224>());
	case HashScheme::SHA256:
		return HashTransformationPtr(std::make_unique<CryptoPP::SHA256>());
	case HashScheme::SHA384:
		return HashTransformationPtr(std::make_unique<CryptoPP::SHA384>());
	case HashScheme::SHA512:
		return HashTransformationPtr(std::make_unique<CryptoPP::SHA512>());
	case HashScheme::SHA3_224:
		return HashTransformationPtr(std::make_unique<CryptoPP::SHA3_224>());
	case HashScheme::SHA3_256:
		return HashTransformationPtr(std::make_unique<CryptoPP::SHA3_256>());
	case HashScheme::SHA3_384:
		return HashTransformationPtr(std::make_unique<CryptoPP::SHA3_384>());
	case HashScheme::SHA3_512:
		return HashTransformationPtr(std::make_unique<CryptoPP::SHA3_512>());
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
	const HashTransformationPtr hash = GetHashFunction(hash_scheme);
	CryptoPP::StringSource(msg, true, new CryptoPP::HashFilter(*hash.get(), new CryptoPP::StringSink(digest)));
	return vector<byte>(digest.begin(), digest.end());
}
