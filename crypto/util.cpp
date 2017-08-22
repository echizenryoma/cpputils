#include "util.h"

using std::string;
using std::vector;

inline string Util::bytes2str(const vector<byte>& bytes)
{
	return string(bytes.begin(), bytes.end());
}

inline vector<byte> Util::str2bytes(const string& str)
{
	return vector<byte>(str.begin(), str.end());
}
