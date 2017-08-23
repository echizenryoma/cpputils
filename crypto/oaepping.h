/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "padding.h"
#include <cryptopp/oaep.h>

namespace crypto
{
	namespace padding
	{
		class OAEPwithHashandMGF1Padding;
	}
}

class crypto::padding::OAEPwithHashandMGF1Padding : public Padding
{
public:
	enum HashScheme
	{
		SHA1 = 1,
		SHA224 = 224,
		SHA256 = 256,
		SHA384 = 384,
		SHA512 = 512
	};

private:
	size_t block_size_;
	HashScheme hash_scheme_;
	vector<byte> label_;

	CryptoPP::OAEP_Base* GetOAEPFunction() const;
public:
	OAEPwithHashandMGF1Padding(size_t block_size, HashScheme hash_scheme, const vector<byte>& label = {});

	/**
	* \brief Adds the given number of padding bytes to the data input.
	* The value of the padding bytes is determined
	* by the specific padding mechanism that implements this
	* interface.
	* \param in_out the input buffer with the data to pad
	* \exception length_error if <code>in_out</code> is too small to hold
	* the padding bytes
	*/
	void Pad(vector<byte>& in_out) override;

	/**
	* \brief Returns the index where padding starts.
	* Given a buffer with data and their padding, this method returns the
	* index where the padding starts.
	* \param in_out the buffer with the data and their padding
	* \return the index where the padding starts, or -1 if the input is
	* not properly padded
	*/
	int Unpad(vector<byte>& in_out) override;

	/**
	* \brief Determines how long the padding will be for a given input length.
	* \param len the length of the data to pad
	* \return the length of the padding
	*/
	int GetPadLength(size_t len) override;
};
