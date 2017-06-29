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
			NoPadding = EVP_PADDING_ZERO,
			PKCS5Padding = EVP_PADDING_PKCS7,
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
		static const const EVP_CIPHER* GetMode(const DES_MODE& mode);
	public:
		static vector<byte> encode(const vector<byte>& data, vector<byte> key, const DES_MODE& mode, const DES_PADDING& padding);
		static vector<byte> decode(const vector<byte>& data, vector<byte> key, const DES_MODE& mode, const DES_PADDING& padding);
	};
}

#endif __DES_H__
