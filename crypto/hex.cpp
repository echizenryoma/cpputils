/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "hex.h"
#include <cryptopp/hex.h>
using std::string;
using std::vector;

string Hex::encode(const byte* message, const size_t& messageSize, const bool& uppercase)
{
	return encode(string(message, message + messageSize), uppercase);
}

string Hex::encode(const vector<byte>& message, const bool& uppercase)
{
	return encode(string(message.begin(), message.end()), uppercase);
}

string Hex::encode(const string& message, const bool& uppercase)
{
	string encoded;
	CryptoPP::StringSource(message, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(encoded), uppercase));
	return encoded;
}

vector<byte> Hex::decode(const string& encoded)
{
	string decoded;
	CryptoPP::StringSource(encoded, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
	return vector<byte>(decoded.begin(), decoded.end());
}
