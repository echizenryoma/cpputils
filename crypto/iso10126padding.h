/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <vector>
using std::vector;

#include <cryptopp/config.h>
#include "padding.h"


/**
* \brief This class implements padding as specified in the W3 XML ENC standard.
* \sa <A HREF="https://github.com/frohoff/jdk8u-jdk/blob/master/src/share/classes/com/sun/crypto/provider/ISO10126Padding.java">jdk8u-jdk/ISO10126Padding.java</A>
* for additional details.
*/
class ISO10126Padding : public Padding
{
	size_t block_size;
public:
	explicit ISO10126Padding(size_t blockSize);

	/**
	* \brief Adds the given number of padding bytes to the data input.
	* The value of the padding bytes is determined
	* by the specific padding mechanism that implements this
	* interface.
	* \param in the input buffer with the data to pad
	* \exception length_error if <code>in</code> is too small to hold
	* the padding bytes
	*/
	void Pad(vector<byte>& in) override;

	/**
	* \brief Returns the index where padding starts.
	* Given a buffer with data and their padding, this method returns the
	* index where the padding starts.
	* \param in the buffer with the data and their padding
	* \return the index where the padding starts, or -1 if the input is
	* not properly padded
	*/
	int Unpad(vector<byte>& in) override;

	/**
	* \brief Determines how long the padding will be for a given input length.
	* \param len the length of the data to pad
	* \return the length of the padding
	*/
	size_t GetPadLength(const size_t& len) override;
};
