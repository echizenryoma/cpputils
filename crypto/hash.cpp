/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "hash.h"
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

vector<byte> crypto::message::digest::Hash::digest(const vector<byte>& msg, const HASH_SCHEME& hash_scheme)
{
	vector<byte> hash;
	switch (hash_scheme)
	{
	case MD4:
		hash.resize(MD4_DIGEST_LENGTH);
		::MD4(msg.data(), msg.size(), hash.data());
		break;
	case MD5:
		hash.resize(MD5_DIGEST_LENGTH);
		::MD5(msg.data(), msg.size(), hash.data());
		break;
	case SHA1:
		hash.resize(SHA_DIGEST_LENGTH);
		::SHA1(msg.data(), msg.size(), hash.data());
		break;
	case SHA224:
		hash.resize(SHA224_DIGEST_LENGTH);
		::SHA224(msg.data(), msg.size(), hash.data());
		break;
	case SHA256:
		hash.resize(SHA256_DIGEST_LENGTH);
		::SHA256(msg.data(), msg.size(), hash.data());
		break;
	case SHA384:
		hash.resize(SHA384_DIGEST_LENGTH);
		::SHA384(msg.data(), msg.size(), hash.data());
		break;
	case SHA512:
		hash.resize(SHA512_DIGEST_LENGTH);
		::SHA512(msg.data(), msg.size(), hash.data());
		break;
	default: 
		throw std::invalid_argument("[invalid_argument] crypto::message::digest::Hash::digest(const vector<byte>&, const HASH_SCHEME&): {hash_scheme} is not support.");
	}
	return hash;
}

vector<byte> crypto::message::digest::Hash::digest(const string& msg, const HASH_SCHEME& hash_scheme)
{
	return digest(vector<byte>(msg.begin(), msg.end()), hash_scheme);
}
