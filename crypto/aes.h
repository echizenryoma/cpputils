/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"

#include "padding.h"
using crypto::padding::Padding;

#include <openssl/ossl_typ.h>

namespace crypto
{
	class Aes;
}

class crypto::Aes
{
public:
	enum PADDING_SCHEME
	{
		ZeroPadding = 0,
		NoPadding = 1,
		PKCS5Padding = 5,
		PKCS7Padding = 7,
		ISO10126Padding = 10126
	};

	enum CIPHER_MODE
	{
		CBC,
		CFB,
		CTR,
		CTS,
		ECB,
		OFB,
		GCM
	};

	enum KEY_SIZE
	{
		AES_128 = 128 / 8,
		AES_192 = 192 / 8,
		AES_256 = 256 / 8,
	};

private:
	static bool CheckKey(const vector<byte>& key);
	static bool CheckKeySize(size_t key_size);

	static bool CheckIV(const vector<byte>& iv);
	static bool CheckIVSize(size_t iv_size);

	static Padding* GetPaadingFunction(PADDING_SCHEME padding_scheme);
	static const EVP_CIPHER* GetChiperFunction(CIPHER_MODE cipher_mode, size_t key_size);
public:
	static vector<byte> radom_key(const KEY_SIZE& key_size = AES_128);

	static vector<byte> radom_iv();
	static vector<byte> default_iv();

	static vector<byte> encrypt(const vector<byte>& msg, const vector<byte>& key, CIPHER_MODE cipher_mode, PADDING_SCHEME padding_scheme, const vector<byte>& iv = default_iv());
	static vector<byte> decrypt(const vector<byte>& cipher, const vector<byte>& key, CIPHER_MODE cipher_mode, PADDING_SCHEME padding_scheme, const vector<byte>& iv = default_iv());
};
