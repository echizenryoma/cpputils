#pragma once

#include <iostream>
#include <vector>
#include <string>
#include "../type.h"
#include "../base64.h"
#include "../des3.h"
using namespace std;


inline int DES3_Test()
{
	vector<byte> key = Crypto::Des3::radom_key(2);
	cout << Base64::encode(key) << endl;
	Crypto::Des3::check_key(key);
	return 0;
}