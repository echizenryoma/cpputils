/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "x932padding.h"

crypto::padding::X932Padding::X932Padding(const size_t block_size): block_size_(block_size)
{
}

void crypto::padding::X932Padding::Pad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;
	if (in.empty())
	{
		return;
	}
	// the number of padding bytes to add
	const size_t len = GetPadLength(in.size());
	out.insert(out.end(), len, 0);
	out.insert(out.end(), 1, static_cast<byte>(len & 0xFF));
}

size_t crypto::padding::X932Padding::Unpad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;

	if (in.empty())
	{
		return 0;
	}

	const byte last_byte = in.back();
	const size_t pad_value = last_byte & 0x0ff;
	if (pad_value > block_size_)
	{
		return -1;
	}
	const size_t start = in.size() - pad_value - 1;
	for (size_t i = 0; i < pad_value; i++)
	{
		if (in[start + i] != 0)
		{
			return -1;
		}
	}
	out.resize(start);
	return start;
}

size_t crypto::padding::X932Padding::GetPadLength(const size_t len) const
{
	return block_size_ - len % block_size_ - 1;
}
