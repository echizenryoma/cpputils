/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
#include <cryptopp/config.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
using std::vector;
using std::string;

class Hash
{
public:
	enum Algorithm
	{
		MD2 = 12,
		MD4 = 14,
		MD5 = 15,
		SHA1 = 1,
		SHA224 = 224,
		SHA256 = 256,
		SHA384 = 384,
		SHA512 = 512
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
	static CryptoPP::SimpleProxyFilter* getFilter(const Encode& encode, CryptoPP::BufferedTransformation* attachment);
	static CryptoPP::HashTransformation* getHashTransformation(const Algorithm& algorithm);
public:
	static vector<byte> caculate(const vector<byte>& message, const Algorithm& algorithm);
	static vector<byte> caculate(const string& message, const Algorithm& algorithm);

	static string caculate(const vector<byte>& message, const Algorithm& algorithm, const Encode& encode);
	static string caculate(const string& message, const Algorithm& algorithm, const Encode& encode);
};
