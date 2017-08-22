/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "iso10126padding.h"
#include <random>
#include <algorithm>

crypto::padding::ISO10126Padding::ISO10126Padding(size_t blockSize)
{
	block_size = blockSize;
}

void crypto::padding::ISO10126Padding::Pad(vector<byte>& in_out)
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
	vector<byte> padding(len);

	static std::random_device rd;
	static std::mt19937 mte(rd());
	std::uniform_int_distribution<unsigned int> dist(0, 0xff);
	std::generate(padding.begin(), padding.end() - 1, [&]() { return static_cast<byte>(dist(mte)); });

	padding.back() = paddingOctet;
	out.insert(out.end(), padding.begin(), padding.end());
}

size_t crypto::padding::ISO10126Padding::Unpad(vector<byte>& in_out)
{
	vector<byte> &in = in_out;
	vector<byte> &out = in_out;
	if (in.empty())
	{
		return 0;
	}

	byte lastByte = in.back();
	size_t padValue = lastByte & 0x0ff;
	if (padValue < 0x01 || padValue > block_size)
	{
		return 0;
	}

	size_t start = in.size() - padValue;
	out.resize(start);
	return start;
}

size_t crypto::padding::ISO10126Padding::GetPadLength(const size_t& len)
{
	return block_size - len % block_size;
}
