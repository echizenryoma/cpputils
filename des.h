#pragma once

#ifndef __DES_H__
#define __DES_H__

#include <vector>
#include <openssl/evp.h>
#include "type.h"
using std::vector;
using std::string;

namespace Crypto
{
	class Des
	{
	public:
		enum DES_PADDING
		{
			NoPadding = EVP_CIPH_NO_PADDING,
			PKCS5Padding = 105,
			PKCS7Padding = EVP_PADDING_PKCS7,
			ISO10126Padding = EVP_PADDING_ISO10126
		};

		enum DES_MODE
		{
			CBC,
			CFB,
			//CTR, //未实现
			//CTS, //未实现
			ECB,
			OFB,
		};

	private:
		static const EVP_CIPHER* get_mode(const DES_MODE& mode);
	public:
		static vector<byte> key(const string& des_key_str);
		static bool check_key(const vector<byte>& des_key);
		static vector<byte> radom_key();
		static vector<byte> encrypt(const vector<byte>& data, const vector<byte>& key, const DES_MODE& mode, const DES_PADDING& padding);
		static vector<byte> decrypt(const vector<byte>& data, const vector<byte>& key, const DES_MODE& mode, const DES_PADDING& padding);
	};
}

#endif __DES_H__
