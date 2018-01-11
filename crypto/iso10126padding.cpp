/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "iso10126padding.h"

crypto::padding::ISO10126Padding::ISO10126Padding(const size_t block_size): block_size_(block_size)
{
}

void crypto::padding::ISO10126Padding::Pad(vector<byte>& in_out) const
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
	vector<byte> padding(len);

	static std::random_device rd;
	static std::mt19937 mte(rd());
	std::uniform_int_distribution<unsigned int> dist(0, 0xff);
	std::generate(padding.begin(), padding.end() - 1, [&]() { return static_cast<byte>(dist(mte)); });

	padding.back() = padding_octet;
	out.insert(out.end(), padding.begin(), padding.end());
}

size_t crypto::padding::ISO10126Padding::Unpad(vector<byte>& in_out) const
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
	out.resize(start);
	return start;
}

size_t crypto::padding::ISO10126Padding::GetPadLength(const size_t len) const
{
	return block_size_ - len % block_size_;
}
