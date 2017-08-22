/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
using std::vector;
using std::string;

#include <cryptopp/config.h>
#include <cryptopp/filters.h>
#include "padding.h"

class Aes
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
		GCM
	};

	enum KeySize
	{
		AES_128 = 128 / 8,
		AES_192 = 192 / 8,
		AES_256 = 256 / 8,
	};

private:
	static bool CheckKey(const vector<byte>& key);
	static bool CheckKeySize(const size_t& key_size);

	static bool CheckIV(const vector<byte>& iv);
	static bool CheckIVSize(const size_t& iv_size);

	static Padding* GetPaadingScheme(const PaddingScheme& padding_scheme);
public:
	static vector<byte> random_key(const KeySize& key_size = AES_128);

	static vector<byte> random_iv();
	static vector<byte> default_iv();

	static vector<byte> encrypt(const vector<byte>& plain, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv = default_iv());
	static vector<byte> decrypt(const vector<byte>& encryption, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv = default_iv());
};
