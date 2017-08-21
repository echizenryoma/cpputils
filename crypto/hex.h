#pragma once

#ifndef __HEX_H__
#define __HEX_H__

#include <vector>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include "type.h"
using std::string;
using std::vector;
using std::exception;

namespace Hex
{
	string encode(const byte* val, const size_t& length);
	string encode(const vector<byte>& val);
	vector<byte> decode(const string& str_base64);

	inline string encode(const byte* val, const size_t& length)
	{
		BIGNUM* bignum_val = BN_bin2bn(val, length, nullptr);
		if (bignum_val == nullptr)
		{
			throw exception(ERR_error_string(ERR_get_error(), nullptr));
		}
		char* hex_buffer = BN_bn2hex(bignum_val);
		string str_hex(hex_buffer);

		OPENSSL_free(hex_buffer);
		BN_free(bignum_val);
		return str_hex;
	}

	inline string encode(const vector<byte>& val)
	{
		return encode(&val[0], val.size());
	}

	inline vector<byte> decode(const string& str_base64)
	{
		BIGNUM* bignum_val = BN_new();
		if (BN_hex2bn(&bignum_val, str_base64.c_str()) < 0)
		{
			throw exception("BN_hex2bn");
		}

		byte* buffer = new byte[BN_num_bytes(bignum_val)];
		int buffer_length = BN_bn2bin(bignum_val, buffer);
		if (buffer_length < 0)
		{
			throw exception("BN_bn2bin");
		}
		vector<byte> val(buffer, buffer + buffer_length);
		OPENSSL_free(buffer);
		BN_free(bignum_val);
		return val;
	}
}

#endif __HEX_H__
