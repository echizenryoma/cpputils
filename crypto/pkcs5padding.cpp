/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "pkcs5padding.h"

crypto::padding::PKCS5Padding::PKCS5Padding(size_t block_size)
{
	block_size_ = block_size;
}

void crypto::padding::PKCS5Padding::Pad(vector<byte>& in_out) const
{
	vector<byte> &in = in_out;
	vector<byte> &out = in_out;
	if (in.empty())
	{
		return;
	}
	// the number of padding bytes to add
	size_t len = GetPadLength(in.size());
	byte paddingOctet = static_cast<byte>(len & 0xff);
	out.insert(out.end(), len, paddingOctet);
}

int crypto::padding::PKCS5Padding::Unpad(vector<byte>& in_out) const
{
	vector<byte> &in = in_out;
	vector<byte> &out = in_out;

	if (in.empty())
	{
		return 0;
	}

	byte lastByte = in.back();
	size_t padValue = lastByte & 0x0ff;
	if (padValue < 0x01 || padValue > block_size_)
	{
		return -1;
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

int crypto::padding::PKCS5Padding::GetPadLength(size_t len) const
{
	return block_size_ - len % block_size_;
}
