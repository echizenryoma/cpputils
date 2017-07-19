#pragma once

#ifndef __TRIPLE_DES_H__
#define __TRIPLE_DES_H__

#include <vector>
#include <openssl/evp.h>
#include <openssl/des.h>
#include "type.h"
using std::vector;
using std::string;

namespace Crypto
{
	class Des
	{
	public:
		enum PADDING
		{
			NoPadding = EVP_CIPH_NO_PADDING,
			PKCS5Padding = EVP_PADDING_PKCS7,
			PKCS7Padding = EVP_PADDING_PKCS7,
			ISO10126Padding = EVP_PADDING_ISO10126
		};

		enum MODE
		{
			CBC,
			CFB,
			//CTR, //Unimplemented
			//CTS, //Unimplemented
			ECB,
			OFB,
		};

		enum KEY_SIZE
		{
			DES = DES_KEY_SZ,
			DES_EDE = 2 * DES_KEY_SZ,
			DES_EDE3 = 3 * DES_KEY_SZ
		};

	private:
		static const EVP_CIPHER* get_mode(const MODE& mode, const size_t& key_size);
		static bool check_cipher_text(const vector<byte>& cipher_text);
	public:
<<<<<<< HEAD
		static bool check_key(const vector<byte>& key);
		static bool check_key_size(const size_t& key_size);
		static vector<byte> radom_key(const KEY_SIZE& key_count);

		static bool check_iv(const vector<byte>& iv);
		static vector<byte> radom_iv();
		static vector<byte> default_iv();

		static vector<byte> encrypt(const vector<byte>& data, const vector<byte>& key, const MODE& mode, const PADDING& padding, const vector<byte>& iv = default_iv());
		static vector<byte> decrypt(const vector<byte>& data, const vector<byte>& key, const MODE& mode, const PADDING& padding, const vector<byte>& iv = default_iv());
=======
		static vector<byte> key(const string& des_key_str);
		static bool check_key(const vector<byte>& des_key);
		static vector<byte> radom_key();

		static bool check_iv(const vector<byte>& IV);

		static vector<byte> encrypt(const vector<byte>& data, const vector<byte>& key, const DES_MODE& mode, const DES_PADDING& padding, const vector<byte>& IV = vector<byte>(DES_KEY_SZ));
		static vector<byte> decrypt(const vector<byte>& data, const vector<byte>& key, const DES_MODE& mode, const DES_PADDING& padding, const vector<byte>& IV = vector<byte>(DES_KEY_SZ));
>>>>>>> triple-des
	};
}

#endif __TRIPLE_DES_H__
