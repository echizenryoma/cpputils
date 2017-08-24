/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"
#include "padding.h"
#include <openssl/pem.h>
#include <memory>
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
		PKCS1Padding = 115,

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

	static Padding* GetPaadingFunction(PaddingScheme padding_scheme, size_t key_size, KeyType key_type = PublicKey, const vector<byte>& label = {});
public:
	static RSA_ptr pubkey(const string& pem_key_str);
	static RSA_ptr privkey(const string& pem_key_str);
	static RSA_ptr key(const string& pem_key_str, KeyType key_type);

	static vector<byte> encrypt(const vector<byte>& ptext, RSA* key, KeyType key_type = PublicKey, PaddingScheme padding_scheme = NoPadding, const vector<byte>& label = {});
	static vector<byte> decrypt(const vector<byte>& ctext, RSA* key, KeyType key_type = PrivateKey, PaddingScheme padding_scheme = NoPadding,  const vector<byte>& label = {});
};
