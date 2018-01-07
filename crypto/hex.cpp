/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"

#include <cryptopp/hex.h>

#include "hex.h"

string crypto::encode::Hex::encode(const vector<byte>& msg, const bool& uppercase)
{
	return encode(string(msg.begin(), msg.end()), uppercase);
}

string crypto::encode::Hex::encode(const string& msg, const bool& uppercase)
{
	string etext;
	CryptoPP::StringSource(msg, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(etext), uppercase));
	return etext;
}

vector<byte> crypto::encode::Hex::decode(const string& etext)
{
	string decoded;
	CryptoPP::StringSource(etext, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
	return vector<byte>(decoded.begin(), decoded.end());
}
