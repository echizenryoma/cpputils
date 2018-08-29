/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "hex.h"

string crypto::encode::Hex::encode(const vector<byte>& msg, bool use_uppercase)
{
	return encode(string(msg.begin(), msg.end()), use_uppercase);
}

string crypto::encode::Hex::encode(const string& msg, bool use_uppercase)
{
	string etext;
	CryptoPP::StringSource(msg, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(etext), use_uppercase));
	return etext;
}

vector<byte> crypto::encode::Hex::decode(const string& hex_str)
{
	string decoded;
	CryptoPP::StringSource(hex_str, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
	return vector<byte>(decoded.begin(), decoded.end());
}
