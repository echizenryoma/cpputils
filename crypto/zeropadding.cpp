/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "zeropadding.h"

crypto::padding::ZeroPadding::ZeroPadding(const size_t block_size): block_size_(block_size)
{
}

void crypto::padding::ZeroPadding::Pad(vector<byte>& in_out) const
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
}

int crypto::padding::ZeroPadding::Unpad(vector<byte>& in_out) const
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
		return -1;
	}
	out.resize(out.size() - (it - in.rbegin()));
	return out.size();
}

int crypto::padding::ZeroPadding::GetPadLength(size_t len) const
{
	return block_size_ - len % block_size_;
}
