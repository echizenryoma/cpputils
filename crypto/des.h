/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
using std::vector;
using std::string;

#include <cryptopp/config.h>
#include <cryptopp/des.h>
#include <cryptopp/filters.h>
#include "padding.h"

class Des
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

	enum CipherScheme
	{
		DES = CryptoPP::DES::KEYLENGTH,
		DESede2 = CryptoPP::DES_EDE2::KEYLENGTH,
		DESede3 = CryptoPP::DES_EDE3::KEYLENGTH,
	};

private:
	static bool CheckKey(const vector<byte>& key);
	static bool CheckIV(const vector<byte>& iv);
	static Padding* GetPaadingScheme(const PaddingScheme& padding_scheme);

	static vector<byte> Encrypt_CBC(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Encrypt_CFB(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Encrypt_CTR(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Encrypt_ECB(const vector<byte>& padded, const vector<byte>& key);
	static vector<byte> Encrypt_OFB(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);

	static vector<byte> Decrypt_CBC(const vector<byte>& cipher, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Decrypt_CFB(const vector<byte>& cipher, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Decrypt_CTR(const vector<byte>& cipher, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Decrypt_ECB(const vector<byte>& cipher, const vector<byte>& key);
	static vector<byte> Decrypt_OFB(const vector<byte>& cipher, const vector<byte>& key, const vector<byte>& iv);
public:
	static vector<byte> random_iv();
	static vector<byte> default_iv();

	static vector<byte> encrypt(const vector<byte>& plain, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv = default_iv());
	static vector<byte> decrypt(const vector<byte>& cipher, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv = default_iv());
};