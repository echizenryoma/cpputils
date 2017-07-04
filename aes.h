#pragma once

#include <vector>
#include <openssl/evp.h>
#include "type.h"
using std::vector;
using std::string;

namespace Crypto
{
	class Aes
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
			AES_128 = 128,
			AES_192 = 192,
			AES_256 = 256,
		};

	private:
		static const EVP_CIPHER* get_mode(const MODE& mode, const KEY_SIZE& key_size);
		static bool check_cipher_text(const vector<byte>& cipher_text);
	public:
		static KEY_SIZE get_key_size(const vector<byte>& key);
		static KEY_SIZE get_key_size(const size_t& key_size);
		static bool check_key(const vector<byte>& aes_key);
		static bool check_key_size(const size_t& aes_key_size);
		static vector<byte> radom_key(const KEY_SIZE& key_size);

		static bool check_iv(const vector<byte>& iv);
		static vector<byte> radom_iv();
		static vector<byte> default_iv();

		static vector<byte> encrypt(const vector<byte>& data, const vector<byte>& key, const MODE& mode, const PADDING& padding, const vector<byte>& iv = default_iv());
		static vector<byte> decrypt(const vector<byte>& data, const vector<byte>& key, const MODE& mode, const PADDING& padding, const vector<byte>& iv = default_iv());
	};
}
