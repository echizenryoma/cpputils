/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"

#include "oaepping.h"
using crypto::padding::OAEP_BasePtr;

OAEP_BasePtr crypto::padding::OAEPwithHashandMGF1Padding::GetOAEPFunction() const
{
	switch (hash_scheme_)
	{
	case MD2:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::Weak::MD2>>());
	case MD4:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::Weak::MD4>>());
	case MD5:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::Weak::MD5>>());
	case SHA1:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::SHA1>>());
	case SHA224:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::SHA224>>());
	case SHA256:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::SHA256>>());
	case SHA384:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::SHA384>>());
	case SHA512:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::SHA512>>());
	case SHA3_224:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::SHA3_224>>());
	case SHA3_256:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::SHA3_256>>());
	case SHA3_384:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::SHA3_384>>());
	case SHA3_512:
		return OAEP_BasePtr(std::make_unique<CryptoPP::OAEP<CryptoPP::SHA3_512>>());
	default:
		throw std::invalid_argument("[invalid_argument] <oaepping.cpp> crypto::padding::OAEPwithHashandMGF1Padding::GetOAEPFunction(): {hash_scheme_}.");
	}
}

crypto::padding::OAEPwithHashandMGF1Padding::OAEPwithHashandMGF1Padding(const size_t block_size, const HashScheme hash_scheme, const vector<byte>& label)
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

	OAEP_BasePtr oaep = GetOAEPFunction();
	CryptoPP::AutoSeededRandomPool rng;

	vector<byte> padded(block_size_);
	oaep.get()->Pad(
		rng,
		in.data(), in.size(),
		padded.data(), padded.size() * 8,
		MakeParameters(CryptoPP::Name::EncodingParameters(), CryptoPP::ConstByteArrayParameter(label_.data(), label_.size(), false))
	);
	out = padded;
}

size_t crypto::padding::OAEPwithHashandMGF1Padding::Unpad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;

	if (in.size() != block_size_)
	{
		throw std::invalid_argument("[invalid_argument] <oaeppadding.cpp> crypto::padding::OAEPwithHashandMGF1Padding::Unpad(vector<byte>& in_out): {in.size()}");
	}

	in.erase(in.begin());

	OAEP_BasePtr oaep = GetOAEPFunction();
	CryptoPP::AutoSeededRandomPool rng;

	vector<byte> ptext(block_size_);
	const CryptoPP::DecodingResult result = oaep.get()->Unpad(
		in.data(), in.size() * 8,
		ptext.data(),
		MakeParameters(CryptoPP::Name::EncodingParameters(), CryptoPP::ConstByteArrayParameter(label_.data(), label_.size(), false))
	);
	ptext.resize(result.messageLength);
	out = ptext;
	return result.messageLength;
}

size_t crypto::padding::OAEPwithHashandMGF1Padding::GetPadLength(const size_t len) const
{
	OAEP_BasePtr oaep = GetOAEPFunction();
	const size_t padding_size = oaep.get()->MaxUnpaddedLength(block_size_ * 8) - len;
	return padding_size;
}
