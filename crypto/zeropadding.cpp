/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "zeropadding.h"

ZeroPadding::ZeroPadding(size_t blockSize)
{
	block_size = blockSize;
}

void ZeroPadding::Pad(vector<byte>& in)
{
	if (in.empty())
	{
		return;
	}
	// the number of padding bytes to add
	size_t len = GetPadLength(in.size());
	in.insert(in.end(), len, 0);
}

int ZeroPadding::Unpad(vector<byte>& in)
{
	if (in.empty())
	{
		return 0;
	}

	size_t start = in.size() - block_size;
	vector<byte>::reverse_iterator it = in.rbegin();
	while (it != in.rend() && *it == 0)
	{
		++it;
	}
	if (it == in.rend())
	{
		return -1;
	}
	in.resize(in.size() - (it - in.rbegin()));
	return in.size();
}

size_t ZeroPadding::GetPadLength(const size_t& len)
{
	return block_size - len % block_size;
}
