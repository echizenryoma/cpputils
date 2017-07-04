#pragma once

#include <iostream>
#include <string>
#include "../aes.h"
#include "../base64.h"
using namespace std;

inline int AES_Test()
{
//	vector<byte> key = Crypto::Aes::radom_key(Crypto::Aes::AES_128);
//	cout << Base64::encode(key) << endl;
//	Crypto::Aes::check_key(key);

	vector<byte> key = Base64::decode("F/Qjk8RuDH8krHnIiRoHxg==");

	string str = "12345678";
	vector<byte> buffer(str.begin(), str.end());
	vector<byte> encrypt_text = Crypto::Aes::encrypt(buffer, key, Crypto::Aes::MODE::ECB, Crypto::Aes::PADDING::PKCS7Padding);
	cout << Base64::encode(encrypt_text) << endl;
	vector<byte> plain_text = Crypto::Aes::decrypt(encrypt_text, key, Crypto::Aes::MODE::ECB, Crypto::Aes::PADDING::PKCS7Padding);
	return 0;
}
