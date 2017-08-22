/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "hmac.h"
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

const EVP_MD* crypto::mac::Hmac::GetHashFunction(const HASH_SCHEME& hash_scheme)
{
	const EVP_MD* hash_function;
	switch (hash_scheme)
	{
	case MD4:
		hash_function = EVP_md4();
		break;
	case MD5: 
		hash_function = EVP_md5();
		break;
	case SHA1: 
		hash_function = EVP_sha1();
		break;
	case SHA224: 
		hash_function = EVP_sha224();
		break;
	case SHA256: 
		hash_function = EVP_sha256();
		break;
	case SHA384: 
		hash_function = EVP_sha384();
		break;
	case SHA512: 
		hash_function = EVP_sha512();
		break;
	default: 
		throw std::invalid_argument("[invalid_argument] crypto::message::digest::Hash::digest(const vector<byte>&, const HASH_SCHEME&): {hash_scheme} is not support.");;
	}
	return hash_function;
}

size_t crypto::mac::Hmac::GetMessageDigestLength(const HASH_SCHEME& hash_scheme)
{
	size_t digest_length;

	switch (hash_scheme)
	{
	case MD4:
		digest_length = MD4_DIGEST_LENGTH;
		break;
	case MD5:
		digest_length = MD5_DIGEST_LENGTH;
		break;
	case SHA1:
		digest_length = SHA_DIGEST_LENGTH;
		break;
	case SHA224:
		digest_length = SHA224_DIGEST_LENGTH;
		break;
	case SHA256:
		digest_length = SHA256_DIGEST_LENGTH;
		break;
	case SHA384:
		digest_length = SHA384_DIGEST_LENGTH;
		break;
	case SHA512:
		digest_length = SHA512_DIGEST_LENGTH;
		break;
	default:
		throw std::invalid_argument("[invalid_argument] crypto::message::digest::Hash::digest(const vector<byte>&, const HASH_SCHEME&): {hash_scheme} is not support.");;
	}
	return digest_length;
}

vector<byte> crypto::mac::Hmac::mac(const vector<byte>& msg, const vector<byte>& key, const HASH_SCHEME& hash_scheme)
{
	size_t hmac_size = GetMessageDigestLength(hash_scheme);
	vector<byte> hmac(hmac_size);
	HMAC(GetHashFunction(hash_scheme), key.data(), key.size(), msg.data(), msg.size(), hmac.data(), &hmac_size);
	return hmac;
}

vector<byte> crypto::mac::Hmac::mac(const string& msg, const vector<byte>& key, const HASH_SCHEME& hash_scheme)
{
	return mac(vector<byte>(msg.begin(), msg.end()), key, hash_scheme);
}
