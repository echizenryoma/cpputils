/*
* Copyright (c) 2012, 2018, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "hex.h"

string crypto::encode::Hex::encode(const string& msg, const bool& use_uppercase)
{
	stringstream hex_stream;
	hex_stream << std::hex << std::internal << std::setfill('0');
	if (use_uppercase)
	{
		hex_stream << std::uppercase;
	}
	for (auto& b : msg)
	{
		hex_stream << std::setw(2) << static_cast<uint16_t>(static_cast<byte>(b));
	}
	return hex_stream.str();
}

string crypto::encode::Hex::encode(const vector<byte>& msg, const bool& use_uppercase)
{
	return encode(string(msg.begin(), msg.end()), use_uppercase);
}

vector<byte> crypto::encode::Hex::decode(const string& hex_str)
{
	if (hex_str.size() % 2 != 0)
	{
		throw invalid_argument("[invalid_argument] <hex.cpp> crypto::encode::Hex::decode(const string&): Odd-length string");
	}

	vector<byte> bytes;
	bytes.reserve(hex_str.size() / 2);
	for (size_t i = 0; i < hex_str.size(); i += 2)
	{
		bytes.push_back(static_cast<byte>(stoul(hex_str.substr(i, 2), 0, 16)));
	}
	return bytes;
}
