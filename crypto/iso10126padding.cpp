/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "iso10126padding.h"
#include <cryptopp/osrng.h>
#include <random>
#include <algorithm>

ISO10126Padding::ISO10126Padding(size_t blockSize)
{
	block_size = blockSize;
}

void ISO10126Padding::Pad(vector<byte>& in)
{
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
	in.insert(in.end(), padding.begin(), padding.end());
}

int ISO10126Padding::Unpad(vector<byte>& in)
{
	if (in.empty())
	{
		return 0;
	}

	byte lastByte = in.back();
	size_t padValue = lastByte & 0x0ff;
	if (padValue < 0x01 || padValue > block_size)
	{
		return -1;
	}

	size_t start = in.size() - padValue;
	in.resize(start);
	return start;
}

size_t ISO10126Padding::GetPadLength(const size_t& len)
{
	return block_size - len % block_size;
}
