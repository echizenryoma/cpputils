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

CryptoPP::SimpleProxyFilter* crypto::message::digest::Hash::getFilter(EncodeScheme encode_scheme, CryptoPP::BufferedTransformation* const attachment)
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
		throw std::invalid_argument("[invalid_argument] <hash.cpp> crypto::message::digest::Hash::getFilter(EncodeScheme, CryptoPP::BufferedTransformation* const): {encode_scheme}.");
	}

	if (filter == nullptr)
	{
		throw std::bad_typeid();
	}
	return filter;
}

CryptoPP::HashTransformation* crypto::message::digest::Hash::getHashTransformation(HashScheme hash_scheme)
{
	CryptoPP::HashTransformation* hash;
	switch (hash_scheme)
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
		throw std::invalid_argument("[invalid_argument] <hash.cpp> crypto::message::digest::Hash::getHashTransformation(HashScheme): {hash_scheme}.");
	}

	if (hash == nullptr)
	{
		throw std::bad_typeid();
	}
	return hash;
}

vector<byte> crypto::message::digest::Hash::digest(const vector<byte>& msg, HashScheme hash_scheme)
{
	return digest(string(msg.begin(), msg.end()), hash_scheme);
}

vector<byte> crypto::message::digest::Hash::digest(const string& msg, HashScheme hash_scheme)
{
	string digest;

	CryptoPP::HashTransformation* hash = getHashTransformation(hash_scheme);
	CryptoPP::StringSource(msg, true, new CryptoPP::HashFilter(*hash, new CryptoPP::StringSink(digest)));

	delete hash;
	return vector<byte>(digest.begin(), digest.end());
}

string crypto::message::digest::Hash::digest(const vector<byte>& msg, HashScheme hash_scheme, EncodeScheme encode_scheme)
{
	return digest(string(msg.begin(), msg.end()), hash_scheme, encode_scheme);
}

string crypto::message::digest::Hash::digest(const string& message, HashScheme algorithm, EncodeScheme encode_scheme)
{
	string digest;

	CryptoPP::HashTransformation* hash = getHashTransformation(algorithm);
	CryptoPP::StringSource(message, true, new CryptoPP::HashFilter(*hash, getFilter(encode_scheme, new CryptoPP::StringSink(digest))));

	delete hash;
	return digest;
}
