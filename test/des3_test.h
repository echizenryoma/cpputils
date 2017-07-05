#pragma once

#include <iostream>
#include <vector>
#include <string>
#include "../type.h"
#include "../base64.h"
#include "../des.h"
using namespace std;

inline int DES3_Test()
{
	vector<byte> key = Crypto::Des::radom_key(Crypto::Des::MOTHED::DES_EDE);
	cout << Base64::encode(key) << endl;
	Crypto::Des::check_key(key);
	return 0;
}
