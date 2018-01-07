/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"

#include "rc4.h"

bool crypto::RC4::CheckKey(const vector<byte>& key)
{
	return CheckKeySize(key.size());
}

bool crypto::RC4::CheckKeySize(size_t key_size)
{
	return key_size >= CryptoPP::Weak::ARC4::MIN_KEYLENGTH && key_size <= CryptoPP::Weak::ARC4::MAX_KEYLENGTH;
}

vector<byte> crypto::RC4::random_key(size_t key_size)
{
	if (!CheckKeySize(key_size))
	{
		throw std::invalid_argument("[invalid_argument] <rc4.cpp> crypto::RC4::random_key(size_t): {key_size}.");
	}

	vector<byte> key(key_size);
	CryptoPP::OS_GenerateRandomBlock(true, key.data(), key.size());
	return key;
}

vector<byte> crypto::RC4::encrypt(const vector<byte>& ptext, const vector<byte>& key)
{
	vector<byte> cipher = ptext;
	CryptoPP::Weak::ARC4 rc4(key.data(), key.size());
	rc4.ProcessString(cipher.data(), cipher.size());
	return cipher;
}

vector<byte> crypto::RC4::decrypt(const vector<byte>& ctext, const vector<byte>& key)
{
	vector<byte> plain = ctext;
	CryptoPP::Weak::ARC4 rc4(key.data(), key.size());
	rc4.ProcessString(plain.data(), plain.size());
	return plain;
}
