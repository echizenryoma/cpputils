/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "base64.h"
#include <cryptopp/base64.h>
#include <cryptopp/basecode.h>
using std::vector;
using std::string;

string Base64::encode(const byte* message, const size_t& messageSize, const Mode& mode, const bool& insertLineBreaks, const int& maxLineLength)
{
	string encoded;
	CryptoPP::SimpleProxyFilter* filter;
	switch (mode)
	{
	case Standard:
		filter = new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), insertLineBreaks, maxLineLength);
		break;
	case URL_Safe:
		filter = new CryptoPP::Base64URLEncoder(new CryptoPP::StringSink(encoded), insertLineBreaks, maxLineLength);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <base64.cpp> HMAC::CalculateDigest(const byte*, const size_t&, const Mode&): {mode}.");
	}

	if (filter == nullptr)
	{
		throw std::bad_typeid();
	}

	CryptoPP::StringSource(message, messageSize, true, filter);
	return encoded;
}

string Base64::encode(const vector<byte>& message, const Mode& mode, const bool& insertLineBreaks, const int& maxLineLength)
{
	return encode(message.data(), message.size(), mode);
}

string Base64::encode(const string& message, const Mode& mode, const bool& insertLineBreaks, const int& maxLineLength)
{
	return encode(reinterpret_cast<const byte*>(message.data()), message.size(), mode);
}

vector<byte> Base64::decode(const string& encoded, const Mode& mode)
{
	string decoded;
	CryptoPP::BaseN_Decoder* filter;
	switch (mode)
	{
	case Standard:
		filter = new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded));
		break;
	case URL_Safe:
		filter = new CryptoPP::Base64URLDecoder(new CryptoPP::StringSink(decoded));
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <base64.cpp> HMAC::CalculateDigest(const byte*, const size_t&, const Mode&): {mode}.");
	}

	if (filter == nullptr)
	{
		throw std::bad_typeid();
	}

	CryptoPP::StringSource(encoded, true, filter);
	return vector<byte>(decoded.begin(), decoded.end());
}
