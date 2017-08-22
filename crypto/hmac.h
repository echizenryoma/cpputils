/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
#include <cryptopp/config.h>
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
using std::vector;
using std::string;

class Hmac
{
public:
	enum Algorithm
	{
		HMAC_MD2 = 2,
		HMAC_MD4 = 4,
		HMAC_MD5 = 5,
		HMAC_SHA1 = 1,
		HMAC_SHA224 = 224,
		HMAC_SHA256 = 256,
		HMAC_SHA384 = 384,
		HMAC_SHA512 = 512
	};

	enum Encode
	{
		Base64 = 64,
		Base64_NewLine_64 = 64064,
		Base64_NewLine_72 = 64072,
		Base64_NewLine_76 = 64076,

		Base64Url = 64100,

		Hex = 16,
		Hex_Uppercase = 1600,
		Hex_Lowercase = 1601
	};

private:
	static CryptoPP::SimpleProxyFilter* GetFilter(const Encode& encode, CryptoPP::BufferedTransformation* attachment);
	static CryptoPP::HMAC_Base* GetHMAC(const Algorithm& algorithm, const vector<byte>& key);
public:
	static vector<byte> calculate(const vector<byte>& plain, const vector<byte>& key, const Algorithm& algorithm);
	static vector<byte> calculate(const string& plain, const vector<byte>& key, const Algorithm& algorithm);

	static string calculate(const vector<byte>& message, const Algorithm& algorithm, const vector<byte>& key, const Encode& encode);
	static string calculate(const string& message, const Algorithm& algorithm, const vector<byte>& key, const Encode& encode);
};
