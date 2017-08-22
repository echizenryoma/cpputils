/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pkcs5padding.h"

crypto::padding::PKCS5Padding::PKCS5Padding(size_t blockSize)
{
	block_size_ = blockSize;
}

void crypto::padding::PKCS5Padding::Pad(vector<byte>& in_out)
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;

	if (in.empty())
	{
		return;
	}
	// the number of padding bytes to add
	size_t len = GetPadLength(in.size());
	byte paddingOctet = static_cast<byte>(len & 0xff);
	out.insert(out.end(), len, paddingOctet);
}

size_t crypto::padding::PKCS5Padding::Unpad(vector<byte>& in_out)
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;

	if (in.empty())
	{
		return 0;
	}

	byte lastByte = in.back();
	size_t padValue = lastByte & 0x0ff;
	if (padValue < 0x01 || padValue > block_size_)
	{
		return 0;
	}
	size_t start = in.size() - padValue;
	for (size_t i = 0; i < padValue; i++)
	{
		if (in[start + i] != lastByte)
		{
			return -1;
		}
	}
	out.resize(start);
	return start;
}

size_t crypto::padding::PKCS5Padding::GetPadLength(const size_t& len)
{
	return block_size_ - len % block_size_;
}
