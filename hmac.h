#pragma once

#ifndef __HMAC_H__
#define __HMAC_H__

#include <string>
#include <vector>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include "type.h"
using namespace std;

namespace Hmac
{
	inline string hamc_md5(const vector<byte>& key, const vector<byte>& message)
	{
		HMAC_CTX* ctx = HMAC_CTX_new();
		if (ctx == nullptr)
		{
			ERR_print_errors_fp(stderr);
			throw exception(ERR_error_string(ERR_get_error(), nullptr));
		}
		HMAC_Init_ex(ctx, &key[0], key.size(), EVP_md5(), nullptr);
		HMAC_Update(ctx, &message[0], message.size());
		byte hash[MD5_DIGEST_LENGTH];
		HMAC_Final(ctx, hash, nullptr);
		HMAC_CTX_free(ctx);
		return Hex::encode(hash, MD5_DIGEST_LENGTH);
	}

	inline string hamc_sha1(const vector<byte>& key, const vector<byte>& message)
	{
		HMAC_CTX* ctx = HMAC_CTX_new();
		if (ctx == nullptr)
		{
			ERR_print_errors_fp(stderr);
			throw exception(ERR_error_string(ERR_get_error(), nullptr));
		}
		HMAC_Init_ex(ctx, &key[0], key.size(), EVP_sha1(), nullptr);
		HMAC_Update(ctx, &message[0], message.size());
		byte hash[SHA_DIGEST_LENGTH];
		HMAC_Final(ctx, hash, nullptr);
		HMAC_CTX_free(ctx);
		return Hex::encode(hash, SHA_DIGEST_LENGTH);
	}

	inline string hamc_sha256(const vector<byte>& key, const vector<byte>& message)
	{
		HMAC_CTX* ctx = HMAC_CTX_new();
		if (ctx == nullptr)
		{
			ERR_print_errors_fp(stderr);
			throw exception(ERR_error_string(ERR_get_error(), nullptr));
		}
		HMAC_Init_ex(ctx, &key[0], key.size(), EVP_sha256(), nullptr);
		HMAC_Update(ctx, &message[0], message.size());
		byte hash[SHA256_DIGEST_LENGTH];
		HMAC_Final(ctx, hash, nullptr);
		HMAC_CTX_free(ctx);
		return Hex::encode(hash, SHA256_DIGEST_LENGTH);
	}

	inline string hamc_sha512(const vector<byte>& key, const vector<byte>& message)
	{
		HMAC_CTX* ctx = HMAC_CTX_new();
		if (ctx == nullptr)
		{
			ERR_print_errors_fp(stderr);
			throw exception(ERR_error_string(ERR_get_error(), nullptr));
		}
		HMAC_Init_ex(ctx, &key[0], key.size(), EVP_sha512(), nullptr);
		HMAC_Update(ctx, &message[0], message.size());
		byte hash[SHA512_DIGEST_LENGTH];
		HMAC_Final(ctx, hash, nullptr);
		HMAC_CTX_free(ctx);
		return Hex::encode(hash, SHA512_DIGEST_LENGTH);
	}
}

#endif __HMAC_H__
