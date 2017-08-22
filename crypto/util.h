#pragma once

#include <vector>
#include <cryptopp/config.h>
using std::string;
using std::vector;

namespace Util
{
	string bytes2str(const vector<byte>& bytes);

	vector<byte> str2bytes(const string& str);
}