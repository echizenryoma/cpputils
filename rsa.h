#pragma once

#ifndef __RSA_H__
#define __RSA_H__

#include <openssl/pem.h>
#include <openssl/err.h>
using namespace std;

namespace Crypto
{
	class Rsa
	{
	public:
		enum KEY_TYPE
		{
			PUBLIC_KEY = 0,
			PRIVATE_KEY = 1,
		};
		
		enum MODE
		{
			None = 0,
			ECB = 1,
		};

		static RSA* key(const string& key_str, const KEY_TYPE& key_type = PUBLIC_KEY)
		{
			BIO* key_content = BIO_new_mem_buf(key_str.c_str(), key_str.length());
			if (key_content == nullptr)
			{
				ERR_print_errors_fp(stderr);
				throw exception(ERR_error_string(ERR_get_error(), nullptr));
			}

			RSA* rsa_key;
			switch (key_type)
			{
			case PUBLIC_KEY:
				rsa_key = PEM_read_bio_RSA_PUBKEY(key_content, nullptr, nullptr, nullptr);
				break;
			case PRIVATE_KEY:
				rsa_key = PEM_read_bio_RSAPrivateKey(key_content, nullptr, nullptr, nullptr);
				break;
			default:
				throw exception("Error key type.");
			}
			BIO_free(key_content);
			if (rsa_key == nullptr)
			{
				ERR_print_errors_fp(stderr);
				throw exception(ERR_error_string(ERR_get_error(), nullptr));
			}
			return rsa_key;
		}

		static vector<byte> encode(const vector<byte>& data, RSA* key, const KEY_TYPE& key_type = PUBLIC_KEY)
		{
			unsigned int rsa_key_size = RSA_size(key);
			string plain_text_str(rsa_key_size - data.size(), 0);
			plain_text_str += string(data.begin(), data.end());
			byte* encrypt_data = new byte[rsa_key_size];
			int encrypt_data_length = RSA_public_encrypt(rsa_key_size, reinterpret_cast<const unsigned char*>(plain_text_str.c_str()), encrypt_data, key, RSA_NO_PADDING);
			if (encrypt_data_length == -1)
			{
				delete[]encrypt_data;
				ERR_print_errors_fp(stderr);
				throw exception(ERR_error_string(ERR_get_error(), nullptr));
			}
			vector<byte> encrypt_text(encrypt_data, encrypt_data + encrypt_data_length);
			delete[]encrypt_data;
			return encrypt_text;
		}

		static vector<byte> decode(const vector<byte>& data, RSA* key, const KEY_TYPE& key_type = PRIVATE_KEY)
		{
			unsigned int rsa_key_size = RSA_size(key);
			unsigned char* plain_data = new unsigned char[rsa_key_size];
			int plain_data_length = RSA_private_decrypt(data.size(), &data[0], plain_data, key, RSA_NO_PADDING);
			if (plain_data_length == -1)
			{
				delete[]plain_data;
				ERR_print_errors_fp(stderr);
				throw exception(ERR_error_string(ERR_get_error(), nullptr));
			}
			for (int i = 0; i < plain_data_length; ++i)
			{
				cout << static_cast<int>(plain_data[i]) << " ";
			}
			cout << endl;
			vector<byte> plain_text(plain_data, plain_data + plain_data_length);
			delete[]plain_data;
			return plain_text;
		}
	};
}

#endif __RSA_H__
