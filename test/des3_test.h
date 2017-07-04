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

	string str = "12345678";
	vector<byte> buffer(str.begin(), str.end());
	vector<byte> encrypt_text = Crypto::Des3::encrypt(buffer, key, Crypto::Des3::DES3_MODE::ECB, Crypto::Des3::DES3_PADDING::PKCS7Padding);
	cout << Base64::encode(encrypt_text) << endl;
	vector<byte> plain_text = Crypto::Des3::decrypt(encrypt_text, key, Crypto::Des3::DES3_MODE::ECB, Crypto::Des3::DES3_PADDING::PKCS7Padding);
	return 0;
}