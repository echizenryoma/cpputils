/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "hex.h"
#include "oaepping.h"
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

inline crypto::padding::OAEPwithHashandMGF1Padding::OAEPwithHashandMGF1Padding(size_t block_size, HashScheme hash_scheme)
{
	block_size_ = block_size;
	hash_scheme_ = hash_scheme;
}

void crypto::padding::OAEPwithHashandMGF1Padding::Pad(vector<byte>& in_out)
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;

	if (in.size() > block_size_)
	{
		throw std::invalid_argument("[invalid_argument] <oaepping.cpp> crypto::padding::OAEPwithHashandMGF1Padding::Pad(vector<byte>&): {in_out.size()}.");
	}

	vector<byte> hash;
	const EVP_MD* hash_function;
	switch (hash_scheme_)
	{
	case SHA1:
		hash_function = EVP_sha1();
		break;
	case SHA224:
		hash_function = EVP_sha224();
		break;
	case SHA256:
		hash_function = EVP_sha256();
		break;
	case SHA384:
		hash_function = EVP_sha384();
		break;
	case SHA512:
		hash_function = EVP_sha512();
		break;

	default:
		throw std::exception("Padding is not support.");
	}
	vector<byte> buffer(block_size_);
	RSA_padding_add_PKCS1_OAEP_mgf1(buffer.data(), buffer.size(), in.data(), in.size(), nullptr, 0, hash_function, nullptr);
	out = buffer;
}

size_t crypto::padding::OAEPwithHashandMGF1Padding::Unpad(vector<byte>& in_out)
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;

	size_t hash_size;
	vector<byte> hash;
	const EVP_MD* hash_function;
	switch (hash_scheme_)
	{
	case SHA1:
		hash = encode::Hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709");
		hash_size = SHA_DIGEST_LENGTH;
		hash_function = EVP_sha1();
		break;
	case SHA224:
		hash = encode::Hex::decode("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
		hash_size = SHA224_DIGEST_LENGTH;
		hash_function = EVP_sha224();
		break;
	case SHA256:
		hash = encode::Hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		hash_size = SHA256_DIGEST_LENGTH;
		hash_function = EVP_sha256();
		break;
	case SHA384:
		hash = encode::Hex::decode("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
		hash_size = SHA384_DIGEST_LENGTH;
		hash_function = EVP_sha384();
		break;
	case SHA512:
		hash = encode::Hex::decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
		hash_size = SHA512_DIGEST_LENGTH;
		hash_function = EVP_sha512();
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <oaepping.cpp> crypto::padding::OAEPwithHashandMGF1Padding::Unpad(vector<byte>&): {hash_scheme_} is not support.");
	}

	size_t db_size = in.size() - hash_size - 1;
	vector<byte> maskedSeed = vector<byte>(in.begin() + 1, in.begin() + 1 + hash_size);
	vector<byte> maskedDb = vector<byte>(in.begin() + 1 + hash_size, in.end());
	vector<byte> seedMask = vector<byte>(hash_size);
	PKCS1_MGF1(&seedMask[0], hash_size, &maskedDb[0], db_size, hash_function);
	vector<byte> seed = vector<byte>(hash_size);
	for (size_t i = 0; i < hash_size; ++i)
	{
		seed[i] = maskedSeed[i] ^ seedMask[i];
	}
	vector<byte> dbMask = vector<byte>(in.size() - hash_size - 1);
	PKCS1_MGF1(&dbMask[0], db_size, &seed[0], hash_size, hash_function);
	vector<byte> db = vector<byte>(db_size);
	for (size_t i = 0; i < db_size; ++i)
	{
		db[i] = maskedDb[i] ^ dbMask[i];
	}
	vector<byte>::iterator it = find(db.begin() + hash_size, db.end(), '\x1');
	if (it == db.end())
	{
		throw std::domain_error("[domain_error] <oaepping.cpp> crypto::padding::OAEPwithHashandMGF1Padding::Unpad(vector<byte>&): {it} cannot find 0x01.");
	}
	vector<byte> m(it + 1, db.end());
	vector<byte> lHash(db.begin(), db.begin() + hash_size);

	if (hash != lHash)
	{
		throw std::runtime_error("[runtime_error] <oaepping.cpp> crypto::padding::OAEPwithHashandMGF1Padding::Unpad(vector<byte>&): {hash} is not correct.");
	}
	out = m;
	return it - db.begin();
}

size_t crypto::padding::OAEPwithHashandMGF1Padding::GetPadLength(const size_t& len)
{
	return 0;
}
