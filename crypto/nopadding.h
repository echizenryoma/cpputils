/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "padding.h"

namespace crypto
{
	namespace padding
	{
		/**
		* \brief This class implements no padding added to a block.
		*/
		class NoPadding;
	}
}

class crypto::padding::NoPadding : public Padding
{
	size_t block_size_;
public:
	explicit NoPadding(size_t blockSize);

	/**
	* \brief Adds the given number of padding bytes to the data input.
	* The value of the padding bytes is determined
	* by the specific padding mechanism that implements this
	* interface.
	* \param in the input buffer with the data to pad
	* \exception length_error if <code>in</code> is too small to hold
	* the padding bytes
	*/
	void Pad(vector<byte> &in) override;

	/**
	* \brief Returns the index where padding starts.
	* Given a buffer with data and their padding, this method returns the
	* index where the padding starts.
	* \param in the buffer with the data and their padding
	* \return the index where the padding starts, or 0 if the input is
	* not properly padded
	*/
	size_t Unpad(vector<byte> &in) override;

	/**
	* \brief Determines how long the padding will be for a given input length.
	* \param len the length of the data to pad
	* \return the length of the padding
	*/
	size_t GetPadLength(const size_t& len) override;
};