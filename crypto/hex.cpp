/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "hex.h"
#include <openssl/asn1.h>
#include <openssl/err.h>

string crypto::encode::Hex::encode(const vector<byte>& msg)
{
	BIGNUM* bignum = BN_bin2bn(msg.data(), msg.size(), nullptr);
	if (bignum == nullptr)
	{
		throw std::runtime_error("[runtime_error] <hex.cpp> crypto::encode::Hex::encode(const vector<byte>&): " + string(ERR_error_string(ERR_get_error(), nullptr)));
	}

	char* hex_buffer = BN_bn2hex(bignum);
	string out(hex_buffer);

	size_t padding_size = msg.size() * 2 - out.size();
	if (padding_size > 0)
	{
		out.insert(out.begin(), padding_size, '0');
	}

	OPENSSL_free(hex_buffer);
	BN_free(bignum);
	return out;
}

string crypto::encode::Hex::encode(const string& msg)
{
	return encode(vector<byte>(msg.begin(), msg.end()));
}

vector<byte> crypto::encode::Hex::decode(const string& encoded)
{
	BIGNUM* bignum = BN_new();

	if (BN_hex2bn(&bignum, encoded.c_str()) < 0)
	{
		throw std::runtime_error("[runtime_error] <hex.cpp> encode::Hex::decode(const string&): {BN_hex2bn(&bignum_val, encoded.c_str()) < 0}");
	}

	vector<byte> out(BN_num_bytes(bignum));
	int out_size = BN_bn2bin(bignum, out.data());
	if (out_size < 0)
	{
		throw std::runtime_error("[runtime_error] <hex.cpp> encode::Hex::decode(const string&): {buffer_length < 0}");
	}

	size_t padding_size = encoded.size() / 2 - out.size();
	if (padding_size > 0)
	{
		out.insert(out.begin(), padding_size, 0);
	}

	BN_free(bignum);
	return out;
}
