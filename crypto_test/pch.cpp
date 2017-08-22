//
// pch.cpp
// Include the standard header and generate the precompiled header.
//

#include "pch.h"

string bytes2str(const vector<byte>& bytes)
{
	return string(bytes.begin(), bytes.end());
}
