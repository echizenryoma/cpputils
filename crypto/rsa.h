/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"
#include <cryptopp/rsa.h>

#include "padding.h"
#include <openssl/pem.h>
using crypto::padding::Padding;

using RSA_ptr = std::unique_ptr<RSA, decltype(&RSA_free)>;

namespace crypto
{
	class Rsa;
}

class crypto::Rsa
{
public:
	enum PaddingScheme
	{
		NoPadding = 0,
		PKCS5Padding = 105,
		PKCS7Padding = 107,

		OAEPPadding = 1,
		OAEPwithSHA1andMGF1Padding = 1,
		OAEPwithSHA224andMGF1Padding = 224,
		OAEPwithSHA256andMGF1Padding = 256,
		OAEPwithSHA384andMGF1Padding = 384,
		OAEPwithSHA512andMGF1Padding = 512
	};

	enum KeyType
	{
		PublicKey = 0,
		PrivateKey = 1,
	};

private:
	static int GetMaxMessageSize(PaddingScheme padding_scheme, size_t key_size);
	static bool CheckMessageSize(PaddingScheme padding_scheme, size_t key_size, size_t msg_size);

//	static vector<byte> PEM2DER(const string& pem, bool private_key);

	static Padding* GetPaadingFunction(PaddingScheme padding_scheme, size_t key_size);
public:
//	static CryptoPP::RSA::PublicKey pubkey(const string& key_str);
//	static CryptoPP::RSA::PrivateKey privkey(const string& key_str);

	static RSA_ptr pubkey(const string& pem_key_str);
	static RSA_ptr privkey(const string& pem_key_str);
	static RSA_ptr key(const string& pem_key_str, KeyType key_type);

	static vector<byte> encrypt(const vector<byte>& msg, RSA* key, PaddingScheme padding_scheme = NoPadding, KeyType key_type = PublicKey);
	static vector<byte> decrypt(const vector<byte>& ctext, RSA* key, PaddingScheme padding_scheme = NoPadding, KeyType key_type = PrivateKey);
};
