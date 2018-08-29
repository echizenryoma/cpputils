/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "pkcs5padding.h"

crypto::padding::PKCS5Padding::PKCS5Padding(const size_t block_size): block_size_(block_size)
{
}

void crypto::padding::PKCS5Padding::Pad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;
	if (in.empty())
	{
		return;
	}
	// the number of padding bytes to add
	const size_t len = GetPadLength(in.size());
	const byte padding_octet = static_cast<byte>(len & 0xff);
	out.insert(out.end(), len, padding_octet);
}

size_t crypto::padding::PKCS5Padding::Unpad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;

	if (in.empty())
	{
		return 0;
	}

	const byte last_byte = in.back();
	const size_t pad_value = last_byte & 0x0ff;
	if (pad_value < 0x01 || pad_value > block_size_)
	{
		return -1;
	}
	const size_t start = in.size() - pad_value;
	for (size_t i = 0; i < pad_value; i++)
	{
		if (in[start + i] != last_byte)
		{
			return -1;
		}
	}
	out.resize(start);
	return start;
}

size_t crypto::padding::PKCS5Padding::GetPadLength(const size_t len) const
{
	return block_size_ - len % block_size_;
}
