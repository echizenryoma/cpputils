/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "base64.h"

string crypto::encode::Base64::encode(const vector<byte>& msg, EncodeScheme encode_sheme, bool new_line, int per_line_length)
{
	string encoded;
	CryptoPP::SimpleProxyFilter* filter;
	switch (encode_sheme)
	{
	case Standard:
		filter = new CryptoPP::Base64Encoder(new CryptoPP::StringSink(encoded), new_line, per_line_length);
		break;
	case URL_Safe:
		filter = new CryptoPP::Base64URLEncoder(new CryptoPP::StringSink(encoded), new_line, per_line_length);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <base64.cpp> crypto::encode::Base64::encode(const vector<byte>&, EncodeScheme, bool, int): {encode_sheme}.");
	}

	if (filter == nullptr)
	{
		throw std::bad_typeid();
	}

	CryptoPP::StringSource(msg.data(), msg.size(), true, filter);
	return encoded;
}

string crypto::encode::Base64::encode(const string& msg, EncodeScheme encode_sheme, bool new_line, int per_line_length)
{
	return encode(vector<byte>(msg.begin(), msg.end()), encode_sheme, new_line, per_line_length);
}

vector<byte> crypto::encode::Base64::decode(const string& base64_str, EncodeScheme encode_mode)
{
	string decoded;
	CryptoPP::BaseN_Decoder* filter;
	switch (encode_mode)
	{
	case Standard:
		filter = new CryptoPP::Base64Decoder(new CryptoPP::StringSink(decoded));
		break;
	case URL_Safe:
		filter = new CryptoPP::Base64URLDecoder(new CryptoPP::StringSink(decoded));
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <base64.cpp> crypto::encode::Base64::decode(const string&, EncodeScheme): {encode_sheme}.");
	}

	if (filter == nullptr)
	{
		throw std::bad_typeid();
	}

	CryptoPP::StringSource(base64_str, true, filter);
	return vector<byte>(decoded.begin(), decoded.end());
}
