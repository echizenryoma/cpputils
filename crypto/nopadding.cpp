/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "nopadding.h"

crypto::padding::NoPadding::NoPadding(size_t block_size)
{
	block_size_ = block_size;
}

void crypto::padding::NoPadding::Pad(vector<byte>& in_out) const
{
	vector<byte> &in = in_out;
	vector<byte> &out = in_out;

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
		out.insert(out.begin() + start, lastBlock.begin(), lastBlock.end());
	}
}

int crypto::padding::NoPadding::Unpad(vector<byte>& in_out) const
{
	vector<byte> &in = in_out;
	vector<byte> &out = in_out;

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
			return -1;
		}
		out.resize(start);
		out.insert(out.end(), it, lastBlock.end());
	}
	start = out.size();
	return start;
}

int crypto::padding::NoPadding::GetPadLength(size_t len) const
{
	return (len / block_size_ + 1) * block_size_ - len;
}
