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
	vector<byte> encrypt_text = Crypto::Des::encrypt(buffer, key, Crypto::Des::MODE::ECB, Crypto::Des::PADDING::PKCS7Padding);
	cout << Base64::encode(encrypt_text) << endl;
	vector<byte> plain_text = Crypto::Des::decrypt(encrypt_text, key, Crypto::Des::MODE::ECB, Crypto::Des::PADDING::PKCS7Padding);
	return 0;
}
