/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "rsa.h"
#include <cryptopp/base64.h>
#include <cryptopp/rng.h>

string RSA::RemovePEMHeaderAndFooter(const string& pem_str, bool isPrivateKey)
{
	static const string PRIVATE_KEY_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
	static const string PRIVATE_KEY_PEM_FOOTER = "-----END RSA PRIVATE KEY-----";

	static const string PUBLIC_KEY_PEM_HEADER = "-----BEGIN PUBLIC KEY-----";
	static const string PUBLIC_KEY_PEM_FOOTER = "-----END PUBLIC KEY-----";

	int pos_start;
	int pos_end;
	if (isPrivateKey)
	{
		pos_start = pem_str.find(PRIVATE_KEY_PEM_HEADER);
		if (pos_start == string::npos)
		{
			throw std::runtime_error("[runtime_error] <rsa.cpp> RSA::RemovePEMHeaderAndFooter(const string&, bool): {PRIVATE_KEY_PEM_HEADER} not found");
		}

		pos_end = pem_str.find(PRIVATE_KEY_PEM_FOOTER);
		if (pos_end == string::npos)
		{
			throw std::runtime_error("[runtime_error] <rsa.cpp> RSA::RemovePEMHeaderAndFooter(const string&, bool): {PRIVATE_KEY_PEM_FOOTER} not found");
		}
		pos_start = pos_start + PRIVATE_KEY_PEM_HEADER.length();
	}
	else
	{
		pos_start = pem_str.find(PUBLIC_KEY_PEM_HEADER);
		if (pos_start == string::npos)
		{
			throw std::runtime_error("[runtime_error] <rsa.cpp> RSA::RemovePEMHeaderAndFooter(const string&, bool): {PUBLIC_KEY_PEM_HEADER} not found");
		}

		pos_end = pem_str.find(PUBLIC_KEY_PEM_FOOTER);
		if (pos_end == string::npos)
		{
			throw std::runtime_error("[runtime_error] <rsa.cpp> RSA::RemovePEMHeaderAndFooter(const string&, bool): {PRIVATE_KEY_PEM_FOOTER} not found");
		}
		pos_start = pos_start + PUBLIC_KEY_PEM_HEADER.length();
	}
	pos_end = pos_end - pos_start;

	string removed_pem_str = pem_str.substr(pos_start, pos_end);
	removed_pem_str.erase(remove(removed_pem_str.begin(), removed_pem_str.end(), '\r'), removed_pem_str.end());
	removed_pem_str.erase(remove(removed_pem_str.begin(), removed_pem_str.end(), '\n'), removed_pem_str.end());
	return removed_pem_str;
}

CryptoPP::RSA::PublicKey RSA::pubkey(const string& key_str)
{
	string pem_key_str = RemovePEMHeaderAndFooter(key_str, false);

	string key;
	CryptoPP::StringSource ss(
		pem_key_str,
		true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(key)
		)
	);
	
	CryptoPP::RSA::PublicKey public_key;
	public_key.BERDecodePublicKey(ss, true, ss.MaxRetrievable());
	return public_key;
}

CryptoPP::RSA::PrivateKey RSA::privkey(const string& key_str)
{
	string pem_key_str = RemovePEMHeaderAndFooter(key_str, true);

	string key;
	CryptoPP::StringSource ss(
		pem_key_str,
		true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(key)
		)
	);

	CryptoPP::RSA::PrivateKey private_key;
	private_key.BERDecodePrivateKey(ss, true, ss.MaxRetrievable());
	return private_key;
}
