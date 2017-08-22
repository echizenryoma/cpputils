/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "hash.h"
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>

CryptoPP::SimpleProxyFilter* Hash::getFilter(const Encode& encode, CryptoPP::BufferedTransformation* attachment)
{
	CryptoPP::SimpleProxyFilter* filter;
	switch (encode)
	{
	case Base64:
		filter = new CryptoPP::Base64Encoder(attachment, false);
		break;
	case Base64_NewLine_64:
		filter = new CryptoPP::Base64Encoder(attachment, true, 64);
		break;
	case Base64_NewLine_72:
		filter = new CryptoPP::Base64Encoder(attachment, true, 72);
		break;
	case Base64_NewLine_76:
		filter = new CryptoPP::Base64Encoder(attachment, true, 76);
		break;
	case Base64Url:
		filter = new CryptoPP::Base64URLEncoder(attachment, false);
		break;
	case Hex:
	case Hex_Uppercase:
		filter = new CryptoPP::HexEncoder(attachment);
		break;
	case Hex_Lowercase:
		filter = new CryptoPP::HexEncoder(attachment, false);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <hash.cpp> Hash::getFilter(const Encode&, CryptoPP::BufferedTransformation*): {encode}.");
	}

	if (filter == nullptr)
	{
		throw std::bad_typeid();
	}
	return filter;
}

CryptoPP::HashTransformation* Hash::getHashTransformation(const Algorithm& algorithm)
{
	CryptoPP::HashTransformation* hash;
	switch (algorithm)
	{
	case MD2:
		hash = new CryptoPP::Weak::MD2();
		break;
	case MD4:
		hash = new CryptoPP::Weak::MD4();
		break;
	case MD5:
		hash = new CryptoPP::Weak::MD5();
		break;
	case SHA1:
		hash = new CryptoPP::SHA();
		break;
	case SHA224:
		hash = new CryptoPP::SHA224();
		break;
	case SHA256:
		hash = new CryptoPP::SHA256();
		break;
	case SHA384:
		hash = new CryptoPP::SHA384();
		break;
	case SHA512:
		hash = new CryptoPP::SHA512();
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <hash.cpp> Hash::getHashTransformation(const Algorithm& algorithm): {algorithm}.");
	}

	if (hash == nullptr)
	{
		throw std::bad_typeid();
	}
	return hash;
}

vector<byte> Hash::caculate(const vector<byte>& message, const Algorithm& algorithm)
{
	return caculate(string(message.begin(), message.end()), algorithm);
}

vector<byte> Hash::caculate(const string& message, const Algorithm& algorithm)
{
	string digest;

	CryptoPP::HashTransformation* hash = getHashTransformation(algorithm);
	CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(*hash, new CryptoPP::StringSink(digest)));

	delete hash;
	return vector<byte>(digest.begin(), digest.end());
}

string Hash::caculate(const vector<byte>& message, const Algorithm& algorithm, const Encode& encode)
{
	return caculate(string(message.begin(), message.end()), algorithm, encode);
}

string Hash::caculate(const string& message, const Algorithm& algorithm, const Encode& encode)
{
	string digest;

	CryptoPP::HashTransformation* hash = getHashTransformation(algorithm);
	CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(*hash, getFilter(encode, new CryptoPP::StringSink(digest))));

	delete hash;
	return digest;
}
