/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "hex.h"

string crypto::encode::Hex::encode(const vector<byte>& msg, const bool& uppercase)
{
	std::stringstream hex_stream;
      hex_stream << std::hex << std::internal << std::setfill('0');
      for(auto &byte : msg)
        hex_stream << std::setw(2) << static_cast<int>(static_cast<unsigned char>(byte));
      return hex_stream.str();
}

vector<byte> crypto::encode::Hex::decode(const string& etext)
{
	string decoded;
	CryptoPP::StringSource(etext, true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(decoded)));
	return vector<byte>(decoded.begin(), decoded.end());
}
