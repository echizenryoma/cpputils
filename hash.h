#pragma once

#ifndef __SHA_H__
#define __SHA_H__

#include <string>
#include <openssl/sha.h>
#include "hex.h"
#include "type.h"
using namespace std;

namespace Hash
{
	inline string sha1(const vector<byte>& data)
	{
		byte hash[SHA_DIGEST_LENGTH];
		SHA_CTX sha_ctx;
		SHA1_Init(&sha_ctx);
		SHA1_Update(&sha_ctx, &data[0], data.size());
		SHA1_Final(hash, &sha_ctx);
		return Hex::encode(hash, SHA_DIGEST_LENGTH);
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

#endif __SHA_H__
