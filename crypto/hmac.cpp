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

CryptoPP::SimpleProxyFilter* crypto::mac::Hmac::GetFilter(EncodeScheme encode_scheme, CryptoPP::BufferedTransformation* const attachment)
{
	CryptoPP::SimpleProxyFilter* filter;
	switch (encode_scheme)
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
		throw std::invalid_argument("[invalid_argument] <hmac.cpp> crypto::mac::Hmac::GetFilter(EncodeScheme, CryptoPP::BufferedTransformation* const): {encode_scheme}.");
	}

	if (filter == nullptr)
	{
		throw std::bad_typeid();
	}
	return filter;
}

CryptoPP::HMAC_Base* crypto::mac::Hmac::GetHmacFunction(HashScheme hash_scheme, const vector<byte>& key)
{
	CryptoPP::HMAC_Base* hmac;
	switch (hash_scheme)
	{
	case MD2:
		hmac = new CryptoPP::HMAC<CryptoPP::Weak::MD2>(&key[0], key.size());
		break;
	case MD4:
		hmac = new CryptoPP::HMAC<CryptoPP::Weak::MD4>(&key[0], key.size());
		break;
	case MD5:
		hmac = new CryptoPP::HMAC<CryptoPP::Weak::MD5>(&key[0], key.size());
		break;
	case SHA1:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA1>(&key[0], key.size());
		break;
	case SHA224:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA224>(&key[0], key.size());
		break;
	case SHA256:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA256>(&key[0], key.size());
		break;
	case SHA384:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA384>(&key[0], key.size());
		break;
	case SHA512:
		hmac = new CryptoPP::HMAC<CryptoPP::SHA512>(&key[0], key.size());
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <hmac.cpp> crypto::mac::Hmac::GetHmacFunction(HashScheme, const vector<byte>&): {hash_scheme}.");
	}

	if (hmac == nullptr)
	{
		throw std::bad_typeid();
	}
	return hmac;
}


vector<byte> crypto::mac::Hmac::mac(const vector<byte>& msg, const vector<byte>& key, HashScheme hash_scheme)
{
	return mac(string(msg.begin(), msg.end()), key, hash_scheme);
}

vector<byte> crypto::mac::Hmac::mac(const string& msg, const vector<byte>& key, HashScheme hash_scheme)
{
	string mac;
	CryptoPP::HMAC_Base* hmac = GetHmacFunction(hash_scheme, key);
	CryptoPP::StringSource(msg, true, new CryptoPP::HashFilter(*hmac, new CryptoPP::StringSink(mac)));
	delete hmac;
	return vector<byte>(mac.begin(), mac.end());
}

string crypto::mac::Hmac::mac(const vector<byte>& msg, const vector<byte>& key, HashScheme hash_scheme, EncodeScheme encode_scheme)
{
	return mac(string(msg.begin(), msg.end()), key, hash_scheme, encode_scheme);
}

string crypto::mac::Hmac::mac(const string& msg, const vector<byte>& key, HashScheme hash_scheme, EncodeScheme encode_scheme)
{
	string digest;

	CryptoPP::HashTransformation* hmac = GetHmacFunction(hash_scheme, key);
	CryptoPP::StringSource(msg, true, new CryptoPP::HashFilter(*hmac, GetFilter(encode_scheme, new CryptoPP::StringSink(digest))));

	delete hmac;
	return digest;
}
