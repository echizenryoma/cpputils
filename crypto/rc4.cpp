/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "rc4.h"
#include <cryptopp/arc4.h>
#include <cryptopp/osrng.h>

bool RC4::CheckKey(const vector<byte>& key)
{
	return CheckKeySize(key.size());
}

bool RC4::CheckKeySize(const size_t& key_size)
{
	return key_size >= CryptoPP::Weak::ARC4::MIN_KEYLENGTH && key_size <= CryptoPP::Weak::ARC4::MAX_KEYLENGTH;
}

vector<byte> RC4::random_key(const size_t& key_size)
{
	if (!CheckKeySize(key_size))
	{
		throw std::invalid_argument("[invalid_argument] <rc4.cpp> RC4::random_key(const size_t&): {key_size}.");
	}

	vector<byte> key(key_size);
	CryptoPP::OS_GenerateRandomBlock(true, key.data(), key.size());
	return key;
}

vector<byte> RC4::encrypt(const vector<byte>& plain, const vector<byte>& key)
{
	vector<byte> cipher = plain;
	CryptoPP::Weak::ARC4 rc4(key.data(), key.size());
	rc4.ProcessString(cipher.data(), cipher.size());
	return cipher;
}

vector<byte> RC4::decrypt(const vector<byte>& cipher, const vector<byte>& key)
{
	vector<byte> plain = cipher;
	CryptoPP::Weak::ARC4 rc4(key.data(), key.size());
	rc4.ProcessString(plain.data(), plain.size());
	return plain;
}