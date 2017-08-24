/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "oaepping.h"
#include <cryptopp/sha.h>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>

CryptoPP::OAEP_Base* crypto::padding::OAEPwithHashandMGF1Padding::GetOAEPFunction() const
{
	CryptoPP::OAEP_Base* oaep;
	switch (hash_scheme_)
	{
	case SHA1:
		oaep = new CryptoPP::OAEP<CryptoPP::SHA1>();
		break;
	case SHA224:
		oaep = new CryptoPP::OAEP<CryptoPP::SHA224>();
		break;
	case SHA256:
		oaep = new CryptoPP::OAEP<CryptoPP::SHA256>();
		break;
	case SHA384:
		oaep = new CryptoPP::OAEP<CryptoPP::SHA384>();
		break;
	case SHA512:
		oaep = new CryptoPP::OAEP<CryptoPP::SHA512>();
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <oaepping.cpp> crypto::padding::OAEPwithHashandMGF1Padding::GetPadLength(size_t): {hash_scheme_}.");
	}
	return oaep;
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
		MakeParameters(CryptoPP::Name::EncodingParameters(), CryptoPP::ConstByteArrayParameter(label_.data(), label_.size(), true))
	);
	delete oaep;
	out = padded;
}

int crypto::padding::OAEPwithHashandMGF1Padding::Unpad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;
	CryptoPP::OAEP_Base* oaep = GetOAEPFunction();
	CryptoPP::AutoSeededRandomPool rng;

	vector<byte> ptext(block_size_);
	CryptoPP::DecodingResult result = oaep->Unpad(
		in.data(), in.size() * 8,
		ptext.data(),
		MakeParameters(CryptoPP::Name::EncodingParameters(), CryptoPP::ConstByteArrayParameter(label_.data(), label_.size(), true))
	);
	delete oaep;
	ptext.resize(result.messageLength);
	out = ptext;
	return result.messageLength;
}

int crypto::padding::OAEPwithHashandMGF1Padding::GetPadLength(size_t len) const
{
	CryptoPP::OAEP_Base* oaep = GetOAEPFunction();
	int padding_size = oaep->MaxUnpaddedLength(block_size_ * 8) - len;
	delete oaep;
	return padding_size;
}
