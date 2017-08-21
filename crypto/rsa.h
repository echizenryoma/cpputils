#pragma once

#ifndef __RSA_H__
#define __RSA_H__

#include <vector>
#include <openssl/rsa.h>
#include "type.h"
using std::vector;
using std::string;

namespace Crypto
{
	class Rsa
	{
	public:
		enum PADDING
		{
			NoPadding = RSA_NO_PADDING,
			PKCS1Padding = RSA_PKCS1_PADDING,
			OAEPPadding = RSA_PKCS1_OAEP_PADDING,
			OAEPwithSHA1andMGF1Padding = 105,
			OAEPwithSHA224andMGF1Padding = 114,
			OAEPwithSHA256andMGF1Padding = 111,
			OAEPwithSHA384andMGF1Padding = 112,
			OAEPwithSHA512andMGF1Padding = 113,
		};

		enum KEY_TYPE
		{
			PUBLIC_KEY = 0,
			PRIVATE_KEY = 1,
		};

	private:
		static vector<byte> RSA_encode_PKCS1_OAEP_padding(const vector<byte>& from, const size_t& key_size, const PADDING& padding);
		static vector<byte> RSA_decode_PKCS1_OAEP_padding(const vector<byte>& from, const PADDING& padding);
	public:
		static bool RSA_message_check_length(const vector<byte>& data, const size_t& key_size, const PADDING& padding);
		static size_t RSA_message_max_length(const size_t& key_size, const PADDING& padding);
		static RSA* key(const string& key_str, const KEY_TYPE& key_type = PUBLIC_KEY);
		static vector<byte> encrypt(const vector<byte>& data, RSA* key, const PADDING& padding = NoPadding, const KEY_TYPE& key_type = PUBLIC_KEY);
		static vector<byte> decrypt(const vector<byte>& data, RSA* key, const PADDING& padding = NoPadding, const KEY_TYPE& key_type = PRIVATE_KEY);
	};
}

#endif __RSA_H__
