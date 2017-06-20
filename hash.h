#pragma once

#ifndef __HASH_H__
#define __HASH_H__

#include <string>
#include <openssl/sha.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include "hex.h"
#include "type.h"
using namespace std;

namespace Hash
{
	inline string md4(const vector<byte>& data)
	{
		byte hash[MD4_DIGEST_LENGTH];
		MD4(&data[0], data.size(), hash);
		return Hex::encode(vector<byte>(hash, hash + MD4_DIGEST_LENGTH));
	}

	inline string md5(const vector<byte>& data)
	{
		byte hash[MD5_DIGEST_LENGTH];
		MD5(&data[0], data.size(), hash);
		return Hex::encode(vector<byte>(hash, hash + MD5_DIGEST_LENGTH));
	}

	inline string sha1(const vector<byte>& data)
	{
		byte hash[SHA_DIGEST_LENGTH];
		SHA_CTX sha_ctx;
		SHA1_Init(&sha_ctx);
		SHA1_Update(&sha_ctx, &data[0], data.size());
		SHA1_Final(hash, &sha_ctx);
		return Hex::encode(hash, SHA_DIGEST_LENGTH);
	}

	inline string sha224(const vector<byte>& data)
	{
		byte hash[SHA224_DIGEST_LENGTH];
		SHA256_CTX sha_ctx;
		SHA224_Init(&sha_ctx);
		SHA224_Update(&sha_ctx, &data[0], data.size());
		SHA224_Final(hash, &sha_ctx);
		return Hex::encode(hash, SHA224_DIGEST_LENGTH);
	}

	inline string sha256(const vector<byte>& data)
	{
		byte hash[SHA256_DIGEST_LENGTH];
		SHA256_CTX sha_ctx;
		SHA256_Init(&sha_ctx);
		SHA256_Update(&sha_ctx, &data[0], data.size());
		SHA256_Final(hash, &sha_ctx);
		return Hex::encode(hash, SHA256_DIGEST_LENGTH);
	}

	inline string sha384(const vector<byte>& data)
	{
		byte hash[SHA384_DIGEST_LENGTH];
		SHA512_CTX sha_ctx;
		SHA384_Init(&sha_ctx);
		SHA384_Update(&sha_ctx, &data[0], data.size());
		SHA384_Final(hash, &sha_ctx);
		return Hex::encode(hash, SHA384_DIGEST_LENGTH);
	}

	inline string sha512(const vector<byte>& data)
	{
		byte hash[SHA512_DIGEST_LENGTH];
		SHA512_CTX sha_ctx;
		SHA512_Init(&sha_ctx);
		SHA512_Update(&sha_ctx, &data[0], data.size());
		SHA512_Final(hash, &sha_ctx);
		return Hex::encode(hash, SHA512_DIGEST_LENGTH);
	}
}

#endif __HASH_H__
