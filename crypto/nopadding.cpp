/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "nopadding.h"

crypto::padding::NoPadding::NoPadding(size_t blockSize)
{
	block_size_ = blockSize;
}

void crypto::padding::NoPadding::Pad(vector<byte>& in)
{
	if (in.empty())
	{
		return;
	}
	// the number of padding bytes to add
	size_t len = GetPadLength(in.size());
	if (len > 0)
	{
		size_t start = in.size() + len - block_size_;
		vector<byte> lastBlock(in.begin() + start, in.end());
		lastBlock.insert(lastBlock.begin(), len, 0);
		in.resize(start);
		in.insert(in.begin() + start, lastBlock.begin(), lastBlock.end());
	}
}

size_t crypto::padding::NoPadding::Unpad(vector<byte>& in)
{
	if (in.empty())
	{
		return 0;
	}

	size_t start = in.size() - block_size_;
	vector<byte> lastBlock(in.begin() + start, in.end());

	if (lastBlock.front() == 0)
	{
		vector<byte>::iterator it = lastBlock.begin();
		while (it != lastBlock.end() && *it == 0)
		{
			++it;
		}
		if (it == lastBlock.end())
		{
			return 0;
		}
		in.resize(start);
		in.insert(in.end(), it, lastBlock.end());
	}
	start = in.size();
	return start;
}

size_t crypto::padding::NoPadding::GetPadLength(const size_t& len)
{
	return (len / block_size_ + 1) * block_size_ - len;
}
