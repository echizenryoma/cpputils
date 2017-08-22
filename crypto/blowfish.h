/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
#include <cryptopp/blowfish.h>
#include <cryptopp/config.h>
#include "padding.h"
using std::vector;
using std::string;

class Blowfish
{
public:
	enum PaddingScheme
	{
		Zero_Padding = 0,
		No_Padding = 1,
		PKCS5_Padding = 5,
		PKCS7_Padding = 7,
		ISO10126_Padding = 10126
	};

	enum CipherMode
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
	static bool CheckKeySize(const size_t& key_size);

	static bool CheckIV(const vector<byte>& iv);
	static bool CheckIVSize(const size_t& iv_size);

	static Padding* GetPaadingScheme(const PaddingScheme& padding_scheme);
public:
	static vector<byte> random_key(const size_t& key_size = CryptoPP::Blowfish::DEFAULT_KEYLENGTH);

	static vector<byte> random_iv();
	static vector<byte> default_iv();

	static vector<byte> encrypt(const vector<byte>& plain, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv = default_iv());
	static vector<byte> decrypt(const vector<byte>& cipher, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv = default_iv());
};
