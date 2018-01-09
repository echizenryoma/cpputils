/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"

#include "padding.h"
using crypto::padding::Padding;

#include <cryptopp/blowfish.h>

namespace crypto
{
	class Blowfish;
}

class crypto::Blowfish
{
public:
	enum class PaddingScheme
	{
		NoPadding = 1,
		PKCS5Padding = 5,
		PKCS7Padding = 7,
		ISO10126Padding = 10126
	};

	enum class CipherMode
	{
		CBC,
		CFB,
		CTR,
		CTS,
		ECB,
		OFB,
	};

private:
	static bool CheckKey(const vector<byte>& key);
	static bool CheckKeySize(size_t key_size);

	static bool CheckIV(const vector<byte>& iv);
	static bool CheckIVSize(size_t iv_size);

	static Padding* GetPaadingFunction(PaddingScheme padding_scheme);
public:
	static vector<byte> random_key(size_t key_size = CryptoPP::Blowfish::DEFAULT_KEYLENGTH);

	static vector<byte> random_iv();
	static vector<byte> default_iv();

	static vector<byte> encrypt(const vector<byte>& ptext, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv = default_iv());
	static vector<byte> decrypt(const vector<byte>& ctext, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv = default_iv());
};
