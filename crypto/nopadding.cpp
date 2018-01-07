/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
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
		vector<byte> last_block(in.begin() + start, in.end());
		last_block.insert(last_block.begin(), len, 0);
		in.resize(start);
		out.insert(out.begin() + start, last_block.begin(), last_block.end());
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
	vector<byte> last_block(in.begin() + start, in.end());

	if (last_block.front() == 0)
	{
		vector<byte>::iterator it = last_block.begin();
		while (it != last_block.end() && *it == 0)
		{
			++it;
		}
		if (it == last_block.end())
		{
			return -1;
		}
		out.resize(start);
		out.insert(out.end(), it, last_block.end());
	}
	start = out.size();
	return start;
}

int crypto::padding::NoPadding::GetPadLength(size_t len) const
{
	return (len / block_size_ + 1) * block_size_ - len;
}
