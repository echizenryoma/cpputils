/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"

#include "padding.h"
using crypto::padding::Padding;

#include <cryptopp/des.h>

namespace crypto
{
	class Des;
}

class crypto::Des
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
		CFB8,
		CTR,
		CTS,
		ECB,
		OFB,
	};

	enum class CipherScheme
	{
		DES = CryptoPP::DES::KEYLENGTH,
		DESede2 = CryptoPP::DES_EDE2::KEYLENGTH,
		DESede3 = CryptoPP::DES_EDE3::KEYLENGTH,
	};

private:
	static bool CheckKey(const vector<byte>& key);
	static bool CheckKeySize(size_t key_size);

	static bool CheckIV(const vector<byte>& iv);
	static bool CheckIVSize(size_t iv_size);

	static Padding* GetPaadingFunction(PaddingScheme padding_scheme);

	static vector<byte> Encrypt_CBC(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Encrypt_CFB(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Encrypt_CFB8(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Encrypt_CTR(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Encrypt_CTS(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Encrypt_ECB(const vector<byte>& padded, const vector<byte>& key);
	static vector<byte> Encrypt_OFB(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv);

	static vector<byte> Decrypt_CBC(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Decrypt_CFB(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Decrypt_CFB8(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Decrypt_CTR(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Decrypt_CTS(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv);
	static vector<byte> Decrypt_ECB(const vector<byte>& ctext, const vector<byte>& key);
	static vector<byte> Decrypt_OFB(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv);
public:
	static vector<byte> random_key(CipherScheme cipher_scheme);

	static vector<byte> random_iv();
	static vector<byte> default_iv();

	static vector<byte> encrypt(const vector<byte>& ptext, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv = default_iv());
	static vector<byte> decrypt(const vector<byte>& ctext, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv = default_iv());
};
