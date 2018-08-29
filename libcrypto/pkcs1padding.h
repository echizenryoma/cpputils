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
		 * \brief This class implements encryption and decryption using PKCS#1 v1.5 padding.
		 */
		class PKCS1v15Padding;
	}
}

class crypto::padding::PKCS1v15Padding: public Padding
{
	int block_size_;
	uint8_t type_version_;
public:
	static const uint8_t PUBLIC_KEY_OPERATION = 2;
	static const uint8_t PRIVATE_KEY_OPERATION = 1;

	PKCS1v15Padding(size_t block_size, uint8_t type_version = 2);

	/**
	* \brief Adds the given number of padding bytes to the data input.
	* The value of the padding bytes is determined
	* by the specific padding mechanism that implements this
	* interface.
	* 
	* EB = 00 || BT || PS || 00 || D
	* The block type BT shall be a single octet indicating the structure of
	* the encryption block. For this version of the document it shall have
	* value 00, 01, or 02. For a private- key operation, the block type
	* shall be 00 or 01. For a public-key operation, it shall be 02.
	*
	* The padding string PS shall consist of k-3-||D|| octets. For block
	* type 00, the octets shall have value 00; for block type 01, they
	* shall have value FF; and for block type 02, they shall be
	* pseudorandomly generated and nonzero. This makes the length of the
	* encryption block EB equal to k.
	* 
	* \param in_out the input buffer with the data to pad
	* \exception length_error if <code>in_out</code> is too small to hold
	* the padding bytes
	* \sa <A HREF="https://tools.ietf.org/html/rfc2313">RFC 2313 - PKCS #1: RSA Encryption Version 1.5</A>
	* for additional details.
	*/
	void Pad(vector<byte>& in_out) const override;

	/**
	* \brief Returns the index where padding starts.
	* Given a buffer with data and their padding, this method returns the
	* index where the padding starts.
	* \param in_out the buffer with the data and their padding
	* \return the index where the padding starts, or -1 if the input is
	* not properly padded
	*/
	size_t Unpad(vector<byte>& in_out) const override;

	/**
	* \brief Determines how long the padding will be for a given input length.
	* \param len the length of the data to pad
	* \return the length of the padding
	*/
	size_t GetPadLength(size_t len) const override;
};
