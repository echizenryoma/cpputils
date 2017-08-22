/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
#include <string>
#include <cryptopp/rsa.h>
using std::string;
using std::vector;

class RSA
{
public:
	enum PaddingScheme
	{
		No_Padding = 0,
		PKCS5_Padding = 5,
		PKCS7_Padding = 7,

		OAEPPadding = 1,
		OAEPwithSHA1andMGF1Padding = 1,
		OAEPwithSHA224andMGF1Padding = 224,
		OAEPwithSHA256andMGF1Padding = 256,
		OAEPwithSHA384andMGF1Padding = 384,
		OAEPwithSHA512andMGF1Padding = 512
	};
private:	
	static string RemovePEMHeader(const string& pem_str, bool isPrivateKey);
public:
	static CryptoPP::RSA::PublicKey pubkey(const string& key_str);
	static CryptoPP::RSA::PrivateKey privkey(const string& key_str);

};
