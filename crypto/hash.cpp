/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "hash.h"
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/filters.h>

CryptoPP::HashTransformation* crypto::message::digest::Hash::GetHashFunction(HashScheme hash_scheme)
{
	CryptoPP::HashTransformation* hash;
	switch (hash_scheme)
	{
	case MD2:
		hash = new CryptoPP::Weak::MD2();
		break;
	case MD4:
		hash = new CryptoPP::Weak::MD4();
		break;
	case MD5:
		hash = new CryptoPP::Weak::MD5();
		break;
	case SHA1:
		hash = new CryptoPP::SHA();
		break;
	case SHA224:
		hash = new CryptoPP::SHA224();
		break;
	case SHA256:
		hash = new CryptoPP::SHA256();
		break;
	case SHA384:
		hash = new CryptoPP::SHA384();
		break;
	case SHA512:
		hash = new CryptoPP::SHA512();
		break;
	case SHA3_224: 
		hash = new CryptoPP::SHA3_224();
		break;
	case SHA3_256: 
		hash = new CryptoPP::SHA3_256();
		break;
	case SHA3_384: 
		hash = new CryptoPP::SHA3_384();
		break;
	case SHA3_512: 
		hash = new CryptoPP::SHA3_512();
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <hash.cpp> crypto::message::digest::Hash::GetHashFunction(HashScheme): {hash_scheme}.");
	}

	if (hash == nullptr)
	{
		throw std::bad_typeid();
	}
	return hash;
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
