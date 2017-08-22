/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
using std::vector;
using std::string;

#include <cryptopp/config.h>

class RC4
{
	static bool CheckKey(const vector<byte>& key);
	static bool CheckKeySize(const size_t& key_size);
public:
	static vector<byte> random_key(const size_t& key_size);

	static vector<byte> encrypt(const vector<byte>& plain, const vector<byte>& key);
	static vector<byte> decrypt(const vector<byte>& cipher, const vector<byte>& key);
};
