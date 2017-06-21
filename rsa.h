#pragma once

#ifndef __RSA_H__
#define __RSA_H__

#include <algorithm>
#include <vector>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "type.h"
using namespace std;

namespace Crypto
{
	namespace Rsa
	{
		enum KEY_TYPE
		{
			PUBLIC_KEY = 0,
			PRIVATE_KEY = 1,
		};

		enum RSA_PADDING
		{
			RSA_NoPadding = RSA_NO_PADDING,
			RSA_PKCS1Padding = RSA_PKCS1_PADDING,
			RSA_OAEPPadding = RSA_PKCS1_OAEP_PADDING,
			RSA_OAEPwithSHA1andMGF1Padding = 1001,
			RSA_OAEPwithSHA224andMGF1Padding = 1224,
			RSA_OAEPwithSHA256andMGF1Padding = 1256,
			RSA_OAEPwithSHA384andMGF1Padding = 1384,
			RSA_OAEPwithSHA512andMGF1Padding = 1512,
		};

		inline RSA* key(const string& key_str, const KEY_TYPE& key_type = PUBLIC_KEY)
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

		inline vector<byte> encode(const vector<byte>& data, RSA* key, const RSA_PADDING& padding = RSA_NoPadding, const KEY_TYPE& key_type = PUBLIC_KEY)
		{
			size_t rsa_key_size = RSA_size(key);
			string plain_text_str(data.begin(), data.end());
			vector<byte> buffer(rsa_key_size, 0);
			int PADDING = padding;
			switch (padding)
			{
			case RSA_NoPadding:
				plain_text_str = string(rsa_key_size - data.size(), 0) + plain_text_str;
				break;
			case RSA_PKCS1Padding: break;
			case RSA_OAEPPadding: break;
			case RSA_OAEPwithSHA1andMGF1Padding:
				PADDING = RSA_NO_PADDING;
				RSA_padding_add_PKCS1_OAEP_mgf1(&buffer[0], buffer.size(), &data[0], data.size(), nullptr, 0, EVP_sha1(), nullptr);
				plain_text_str = string(buffer.begin(), buffer.end());
				break;
			case RSA_OAEPwithSHA224andMGF1Padding:
				PADDING = RSA_NO_PADDING;
				RSA_padding_add_PKCS1_OAEP_mgf1(&buffer[0], buffer.size(), &data[0], data.size(), nullptr, 0, EVP_sha224(), nullptr);
				plain_text_str = string(buffer.begin(), buffer.end());
				break;
			case RSA_OAEPwithSHA256andMGF1Padding:
				PADDING = RSA_NO_PADDING;
				RSA_padding_add_PKCS1_OAEP_mgf1(&buffer[0], buffer.size(), &data[0], data.size(), nullptr, 0, EVP_sha256(), nullptr);
				plain_text_str = string(buffer.begin(), buffer.end());
				break;
			case RSA_OAEPwithSHA384andMGF1Padding:
				PADDING = RSA_NO_PADDING;
				RSA_padding_add_PKCS1_OAEP_mgf1(&buffer[0], buffer.size(), &data[0], data.size(), nullptr, 0, EVP_sha384(), nullptr);
				plain_text_str = string(buffer.begin(), buffer.end());
				break;
			case RSA_OAEPwithSHA512andMGF1Padding:
				PADDING = RSA_NO_PADDING;
				RSA_padding_add_PKCS1_OAEP_mgf1(&buffer[0], buffer.size(), &data[0], data.size(), nullptr, 0, EVP_sha512(), nullptr);
				plain_text_str = string(buffer.begin(), buffer.end());
				break;
			default:
				throw exception("Padding is unsupported.");
			}
			byte* encrypt_data = new byte[rsa_key_size];
			int encrypt_data_length;
			switch (key_type)
			{
			case PUBLIC_KEY:
				encrypt_data_length = RSA_public_encrypt(plain_text_str.size(), reinterpret_cast<const byte*>(plain_text_str.c_str()), encrypt_data, key, PADDING);
				break;
			case PRIVATE_KEY:
				encrypt_data_length = RSA_private_encrypt(plain_text_str.size(), reinterpret_cast<const byte*>(plain_text_str.c_str()), encrypt_data, key, PADDING);
				break;
			default:
				throw exception("Error key type.");
			}
			if (encrypt_data_length < 0)
			{
				delete[]encrypt_data;
				ERR_print_errors_fp(stderr);
				throw exception(ERR_error_string(ERR_get_error(), nullptr));
			}
			vector<byte> encrypt_text(encrypt_data, encrypt_data + encrypt_data_length);
			delete[]encrypt_data;
			return encrypt_text;
		}

		inline vector<byte> decode(const vector<byte>& data, RSA* key, const RSA_PADDING& padding = RSA_NoPadding, const KEY_TYPE& key_type = PRIVATE_KEY)
		{
			size_t rsa_key_size = RSA_size(key);
			byte* plain_data = new byte[rsa_key_size];
			int plain_data_length;

			int PADDING = padding;
			switch (padding)
			{
			case RSA_NoPadding: break;
			case RSA_PKCS1Padding: break;
			case RSA_OAEPPadding: break;
			case RSA_OAEPwithSHA1andMGF1Padding:
			case RSA_OAEPwithSHA224andMGF1Padding:
			case RSA_OAEPwithSHA256andMGF1Padding:
			case RSA_OAEPwithSHA384andMGF1Padding:
			case RSA_OAEPwithSHA512andMGF1Padding:
				PADDING = RSA_PKCS1_OAEP_PADDING;
				break;
			default:
				throw exception("Padding is unsupported.");
			}

			switch (key_type)
			{
			case PUBLIC_KEY:
				plain_data_length = RSA_public_decrypt(data.size(), &data[0], plain_data, key, PADDING);
				break;
			case PRIVATE_KEY:
				plain_data_length = RSA_private_decrypt(data.size(), &data[0], plain_data, key, PADDING);
				break;
			default:
				throw exception("Error key type.");
			}
			if (plain_data_length < 0)
			{
				delete[]plain_data;
				ERR_print_errors_fp(stderr);
				throw exception(ERR_error_string(ERR_get_error(), nullptr));
			}
			vector<byte> plain_text(plain_data, plain_data + plain_data_length);
			size_t pos = 0;
			switch (padding)
			{
			case RSA_NoPadding:
				while (pos < plain_text.size() && plain_text[pos] == 0)
				{
					pos++;
				}
				if (pos < plain_text.size())
				{
					plain_text = vector<byte>(&plain_text[pos], &plain_text[0] + plain_text.size());
				}
				else
				{
					plain_text = vector<byte>();
				}
				break;
			case RSA_PKCS1Padding: break;
			case RSA_OAEPPadding: break;
			case RSA_OAEPwithSHA1andMGF1Padding: break;
			default:
				throw exception("Padding is unsupported.");
			}
			delete[]plain_data;
			return plain_text;
		}
	}
}

#endif __RSA_H__
