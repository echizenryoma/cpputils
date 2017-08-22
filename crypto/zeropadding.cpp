/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "zeropadding.h"

crypto::padding::ZeroPadding::ZeroPadding(size_t blockSize)
{
	block_size_ = blockSize;
}

void crypto::padding::ZeroPadding::Pad(vector<byte>& in_out)
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;
	if (in.empty())
	{
		return;
	}
	// the number of padding bytes to add
	size_t len = GetPadLength(in.size());
	out.insert(out.end(), len, 0);
}

size_t crypto::padding::ZeroPadding::Unpad(vector<byte>& in_out)
{
	vector<byte>& in = in_out;
	vector<byte>& out = in_out;
	if (in.empty())
	{
		return 0;
	}

	size_t start = in.size() - block_size_;
	vector<byte>::reverse_iterator it = in.rbegin();
	while (it != in.rend() && *it == 0)
	{
		++it;
	}
	if (it == in.rend())
	{
		return 0;
	}
	out.resize(out.size() - (it - in.rbegin()));
	return out.size();
}

size_t crypto::padding::ZeroPadding::GetPadLength(const size_t& len)
{
	return block_size_ - len % block_size_;
}
