/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include "type.h"

namespace crypto
{
	namespace padding
	{
		class Padding;
	}
}

class crypto::padding::Padding
{
public:
	virtual ~Padding() = default;

	/**
	 * \brief Adds the given number of padding bytes to the data input.
	 * The value of the padding bytes is determined
	 * by the specific padding mechanism that implements this
	 * interface.
	 * \param in_out the input buffer with the data to pad
	 */
	virtual void Pad(vector<byte> &in_out) = 0;
	
	/**
	 * \brief Returns the index where padding starts.
	 * Given a buffer with data and their padding, this method returns the
	 * index where the padding starts.
	 * \param in_out the buffer with the data and their padding
	 * \return the index where the padding starts, or 0 if the input is
	 * not properly padded
	 */
	virtual size_t Unpad(vector<byte> &in_out) = 0;
	
	/**
	 * \brief Determines how long the padding will be for a given input length.
	 * \param len the length of the data to pad
	 * \return the length of the padding
	 */
	virtual size_t GetPadLength(const size_t& len) = 0;
};