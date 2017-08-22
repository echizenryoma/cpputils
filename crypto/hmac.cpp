/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "hmac.h"
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>
using std::string;
using std::vector;

CryptoPP::SimpleProxyFilter* Hmac::GetFilter(const Encode& encode, CryptoPP::BufferedTransformation* attachment)
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
		throw std::invalid_argument("[invalid_argument] <hmac.cpp> Hash::getFilter(const Encode&, CryptoPP::BufferedTransformation*): {encode}.");
	}

	if (filter == nullptr)
	{
		throw std::bad_typeid();
	}
	return filter;
}

CryptoPP::HMAC_Base* Hmac::GetHMAC(const Algorithm& algorithm, const vector<byte>& key)
{
	CryptoPP::HMAC_Base* hmac;
	switch (algorithm)
	{
	case HMAC_MD2:
		hmac = new CryptoPP::HMAC<CryptoPP::Weak::MD2>(&key[0], key.size());
		break;
	case HMAC_MD4:
		hmac = new CryptoPP::HMAC<CryptoPP::Weak::MD4>(&key[0], key.size());
		break;
	case HMAC_MD5:
		hmac = new CryptoPP::HMAC<CryptoPP::Weak::MD5>(&key[0], key.size());
		break;
	case HMAC_SHA1:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA1>(&key[0], key.size());
		break;
	case HMAC_SHA224:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA224>(&key[0], key.size());
		break;
	case HMAC_SHA256:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA256>(&key[0], key.size());
		break;
	case HMAC_SHA384:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA384>(&key[0], key.size());
		break;
	case HMAC_SHA512:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA512>(&key[0], key.size());
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <hmac.cpp> Hmac::calculate(const string&, const vector<byte>&, const Algorithm&): {algorithm}.");
	}

	if (hmac == nullptr)
	{
		throw std::bad_typeid();
	}
	return hmac;
}



vector<byte> Hmac::calculate(const vector<byte>& plain, const vector<byte>& key, const Algorithm& algorithm)
{
	return calculate(string(plain.begin(), plain.end()), key, algorithm);
}

vector<byte> Hmac::calculate(const string& plain, const vector<byte>& key, const Algorithm& algorithm)
{
	string mac;
	CryptoPP::HMAC_Base* hmac = GetHMAC(algorithm, key);
	CryptoPP::StringSource(plain, true, new CryptoPP::HashFilter(*hmac, new CryptoPP::StringSink(mac)));
	delete hmac;
	return vector<byte>(mac.begin(), mac.end());
}

string Hmac::calculate(const vector<byte>& message, const Algorithm& algorithm, const vector<byte>& key, const Encode& encode)
{
	return calculate(string(message.begin(), message.end()), algorithm, key, encode);
}

string Hmac::calculate(const string& message, const Algorithm& algorithm, const vector<byte>& key, const Encode& encode)
{
	string digest;

	CryptoPP::HashTransformation* hmac = GetHMAC(algorithm, key);
	CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(*hmac, GetFilter(encode, new CryptoPP::StringSink(digest))));

	delete hmac;
	return digest;
}
