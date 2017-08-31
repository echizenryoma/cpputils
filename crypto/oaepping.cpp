/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "oaepping.h"
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>

CryptoPP::OAEP_Base* crypto::padding::OAEPwithHashandMGF1Padding::GetOAEPFunction() const
{
	switch (hash_scheme_)
	{
	case MD2:
		return new CryptoPP::OAEP<CryptoPP::Weak::MD2>();
	case MD4:
		return new CryptoPP::OAEP<CryptoPP::Weak::MD4>();
	case MD5:
		return new CryptoPP::OAEP<CryptoPP::Weak::MD5>();
	case SHA1:
		return new CryptoPP::OAEP<CryptoPP::SHA1>();
	case SHA224:
		return new CryptoPP::OAEP<CryptoPP::SHA224>();
	case SHA256:
		return new CryptoPP::OAEP<CryptoPP::SHA256>();
	case SHA384:
		return new CryptoPP::OAEP<CryptoPP::SHA384>();
	case SHA512:
		return new CryptoPP::OAEP<CryptoPP::SHA512>();
	case SHA3_224:
		return new CryptoPP::OAEP<CryptoPP::SHA3_224>();
	case SHA3_256:
		return new CryptoPP::OAEP<CryptoPP::SHA3_256>();
	case SHA3_384:
		return new CryptoPP::OAEP<CryptoPP::SHA3_384>();
	case SHA3_512:
		return new CryptoPP::OAEP<CryptoPP::SHA3_512>();
	default:
		throw std::invalid_argument("[invalid_argument] <oaepping.cpp> crypto::padding::OAEPwithHashandMGF1Padding::GetPadLength(size_t): {hash_scheme_}.");
	}
}

crypto::padding::OAEPwithHashandMGF1Padding::OAEPwithHashandMGF1Padding(size_t block_size, HashScheme hash_scheme, const vector<byte>& label)
{
	block_size_ = block_size;
	hash_scheme_ = hash_scheme;
	label_ = label;
}

void crypto::padding::OAEPwithHashandMGF1Padding::Pad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;

	if (in.size() >= static_cast<size_t>(GetPadLength(0)))
	{
		throw std::invalid_argument("[invalid_argument] <oaeppadding.cpp> crypto::padding::OAEPwithHashandMGF1Padding::Pad(vector<byte>& in_out): {in.size()} is too long.");
	}

	CryptoPP::OAEP_Base* oaep = GetOAEPFunction();
	CryptoPP::AutoSeededRandomPool rng;

	vector<byte> padded(block_size_);
	oaep->Pad(
		rng,
		in.data(), in.size(),
		padded.data(), padded.size() * 8,
		MakeParameters(CryptoPP::Name::EncodingParameters(), CryptoPP::ConstByteArrayParameter(label_.data(), label_.size(), false))
	);
	delete oaep;
	out = padded;
}

int crypto::padding::OAEPwithHashandMGF1Padding::Unpad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;

	if (in.size() != block_size_)
	{
		throw std::invalid_argument("[invalid_argument] <oaeppadding.cpp> crypto::padding::OAEPwithHashandMGF1Padding::Unpad(vector<byte>& in_out): {in.size()}");
	}

	in.erase(in.begin());

	CryptoPP::OAEP_Base* oaep = GetOAEPFunction();
	CryptoPP::AutoSeededRandomPool rng;

	vector<byte> ptext(block_size_);
	const CryptoPP::DecodingResult result = oaep->Unpad(
		in.data(), in.size() * 8,
		ptext.data(),
		MakeParameters(CryptoPP::Name::EncodingParameters(), CryptoPP::ConstByteArrayParameter(label_.data(), label_.size(), false))
	);
	delete oaep;
	ptext.resize(result.messageLength);
	out = ptext;
	return result.messageLength;
}

int crypto::padding::OAEPwithHashandMGF1Padding::GetPadLength(size_t len) const
{
	CryptoPP::OAEP_Base* oaep = GetOAEPFunction();
	const int padding_size = oaep->MaxUnpaddedLength(block_size_ * 8) - len;
	delete oaep;
	return padding_size;
}
