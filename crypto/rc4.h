/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"

namespace crypto
{
	class RC4;
}

class crypto::RC4
{
	static bool CheckKey(const vector<byte>& key);
	static bool CheckKeySize(size_t key_size);
public:
	static vector<byte> random_key(size_t key_size);

	static vector<byte> encrypt(const vector<byte>& plain, const vector<byte>& key);
	static vector<byte> decrypt(const vector<byte>& cipher, const vector<byte>& key);
};
