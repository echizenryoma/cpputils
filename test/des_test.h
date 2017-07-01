#pragma once

#include <iostream>
#include <string>
#include "../des.h"
#include "../base64.h"
using namespace std;

inline int DES_Test()
{
	vector<byte> key = Base64::decode("MTIyNDQ3Nzg=");

	string str = "12345678";
	vector<byte> buffer(str.begin(), str.end());
	vector<byte> encrypt_text = Crypto::Des::encode(buffer, key, Crypto::Des::DES_MODE::ECB, Crypto::Des::DES_PADDING::PKCS5Padding);
	cout << Base64::encode(encrypt_text) << endl;
	return 0;
}
