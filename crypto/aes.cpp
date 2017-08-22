/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "aes.h"
#include "zeropadding.h"
#include "pkcs5padding.h"
#include "pkcs7padding.h"
#include "iso10126padding.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <memory>

using EVP_CIPHER_CTX_free_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

bool crypto::Aes::CheckKey(const vector<byte>& key)
{
	return CheckKeySize(key.size());
}

bool crypto::Aes::CheckKeySize(size_t key_size)
{
	switch (key_size)
	{
	case AES_128:
	case AES_192:
	case AES_256:
		return true;
	default:
		return false;
	}
}

bool crypto::Aes::CheckIV(const vector<byte>& iv)
{
	return CheckIVSize(iv.size());
}

bool crypto::Aes::CheckIVSize(size_t iv_size)
{
	return iv_size == AES_BLOCK_SIZE;
}

Padding* crypto::Aes::GetPaadingFunction(PADDING_SCHEME padding_scheme)
{
	Padding* padding_function;
	switch (padding_scheme)
	{
	case ZeroPadding:
		padding_function = new padding::ZeroPadding(AES_BLOCK_SIZE);
		break;
	case PKCS5Padding:
		padding_function = new padding::PKCS5Padding(AES_BLOCK_SIZE);
		break;
	case PKCS7Padding:
		padding_function = new padding::PKCS7Padding(AES_BLOCK_SIZE);
		break;
	case ISO10126Padding:
		padding_function = new padding::ISO10126Padding(AES_BLOCK_SIZE);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetPaadingFunction(PADDING_SCHEME padding_scheme): {padding_scheme} is not support.");
	}
	return padding_function;
}

const EVP_CIPHER* crypto::Aes::GetChiperFunction(CIPHER_MODE cipher_mode, size_t key_size)
{
	const EVP_CIPHER* cipher_function;

	switch (cipher_mode)
	{
	case CBC:
	case CTS:
		switch (key_size)
		{
		case AES_128:
			cipher_function = EVP_aes_128_cbc();
			break;
		case AES_192:
			cipher_function = EVP_aes_192_cbc();
			break;
		case AES_256:
			cipher_function = EVP_aes_256_cbc();
			break;
		default:
			throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetChiperFunction(CIPHER_MODE, KEY_SIZE): {key_size} is not support.");
		}
		break;
	case CFB:
		switch (key_size)
		{
		case AES_128:
			cipher_function = EVP_aes_128_cfb();
			break;
		case AES_192:
			cipher_function = EVP_aes_192_cfb();
			break;
		case AES_256:
			cipher_function = EVP_aes_256_cfb();
			break;
		default:
			throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetChiperFunction(CIPHER_MODE, KEY_SIZE): {key_size} is not support.");
		}
		break;
	case CTR:
		switch (key_size)
		{
		case AES_128:
			cipher_function = EVP_aes_128_ctr();
			break;
		case AES_192:
			cipher_function = EVP_aes_192_ctr();
			break;
		case AES_256:
			cipher_function = EVP_aes_256_ctr();
			break;
		default:
			throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetChiperFunction(CIPHER_MODE, KEY_SIZE): {key_size} is not support.");
		}
		break;
	case ECB:
		switch (key_size)
		{
		case AES_128:
			cipher_function = EVP_aes_128_ecb();
			break;
		case AES_192:
			cipher_function = EVP_aes_192_ecb();
			break;
		case AES_256:
			cipher_function = EVP_aes_256_ecb();
			break;
		default:
			throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetChiperFunction(CIPHER_MODE, KEY_SIZE): {key_size} is not support.");
		}
		break;
	case OFB:
		switch (key_size)
		{
		case AES_128:
			cipher_function = EVP_aes_128_ecb();
			break;
		case AES_192:
			cipher_function = EVP_aes_192_ecb();
			break;
		case AES_256:
			cipher_function = EVP_aes_256_ecb();
			break;
		default:
			throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetChiperFunction(CIPHER_MODE, KEY_SIZE): {key_size} is not support.");
		}
		break;
	case GCM:
		switch (key_size)
		{
		case AES_128:
			cipher_function = EVP_aes_128_gcm();
			break;
		case AES_192:
			cipher_function = EVP_aes_192_gcm();
			break;
		case AES_256:
			cipher_function = EVP_aes_256_gcm();
			break;
		default:
			throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetChiperFunction(CIPHER_MODE, KEY_SIZE): {key_size} is not support.");
		}
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetChiperFunction(CIPHER_MODE, KEY_SIZE): {cipher_mode} is not support.");
	}
	return cipher_function;
}

vector<byte> crypto::Aes::radom_key(const KEY_SIZE& key_size)
{
	if (CheckKeySize(key_size))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetChiperFunction(CIPHER_MODE, KEY_SIZE): {key_size} is not support.");
	}

	vector<byte> key(key_size);
	if (!RAND_bytes(key.data(), key.size()))
	{
		throw std::bad_alloc();
	}
	return key;
}

vector<byte> crypto::Aes::radom_iv()
{
	vector<byte> iv(AES_BLOCK_SIZE);
	if (!RAND_bytes(&iv[0], AES_BLOCK_SIZE))
	{
		throw std::bad_alloc();
	}
	return iv;
}

vector<byte> crypto::Aes::default_iv()
{
	return vector<byte>(AES_BLOCK_SIZE);
}

vector<byte> crypto::Aes::encrypt(const vector<byte>& msg, const vector<byte>& key, CIPHER_MODE cipher_mode, PADDING_SCHEME padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::encrypt(const vector<byte>&, const vector<byte>&, CIPHER_MODE, PADDING_SCHEME, const vector<byte>&): {key_size} is not support.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::encrypt(const vector<byte>&, const vector<byte>&, CIPHER_MODE, PADDING_SCHEME, const vector<byte>&): {iv} is not support.");
	}

	EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	EVP_CIPHER_CTX_set_padding(ctx.get(), EVP_CIPH_NO_PADDING);

	int rc = EVP_EncryptInit_ex(ctx.get(), GetChiperFunction(cipher_mode, key.size()), nullptr, key.data(), iv.data());
	if (rc != 1)
	{
		throw std::runtime_error("[runtime_error] <aes.cpp> crypto::Aes::encrypt(const vector<byte>&, const vector<byte>&, CIPHER_MODE, PADDING_SCHEME, const vector<byte>&): {EVP_EncryptInit_ex} failed.");
	}

	vector<byte> ptext = msg;
	if (padding_scheme != NoPadding)
	{
		Padding* padding_function = GetPaadingFunction(padding_scheme);
		padding_function->Pad(ptext);
	}

	vector<byte> ctext(ptext.size());
	int out_size = 0;

	rc = EVP_EncryptUpdate(ctx.get(), ctext.data(), &out_size, ptext.data(), ptext.size());
	if (rc != 1)
	{
		throw std::runtime_error("[runtime_error] <aes.cpp> crypto::Aes::encrypt(const vector<byte>&, const vector<byte>&, CIPHER_MODE, PADDING_SCHEME, const vector<byte>&): {EVP_EncryptUpdate} failed.");
	}
	return ctext;
}

vector<byte> crypto::Aes::decrypt(const vector<byte>& cipher, const vector<byte>& key, CIPHER_MODE cipher_mode, PADDING_SCHEME padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::decrypt(const vector<byte>&, const vector<byte>&, CIPHER_MODE, PADDING_SCHEME, const vector<byte>&): {key_size} is not support.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::decrypt(const vector<byte>&, const vector<byte>&, CIPHER_MODE, PADDING_SCHEME, const vector<byte>&): {iv} is not support.");
	}
	
	EVP_CIPHER_CTX_free_ptr ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
	EVP_CIPHER_CTX_set_padding(ctx.get(), EVP_CIPH_NO_PADDING);

	int rc = EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data());
	if (rc != 1)
	{
		throw std::runtime_error("[runtime_error] <aes.cpp> crypto::Aes::decrypt(const vector<byte>&, const vector<byte>&, CIPHER_MODE, PADDING_SCHEME, const vector<byte>&): {EVP_DecryptInit_ex} failed.");
	}

	vector<byte> ptext(cipher.size());
	const vector<byte> &ctext = cipher;

	int out_size = ptext.size();
	rc = EVP_DecryptUpdate(ctx.get(), ptext.data(), &out_size, ctext.data(), ctext.size());
	if (rc != 1)
	{
		throw std::runtime_error("[runtime_error] <aes.cpp> crypto::Aes::decrypt(const vector<byte>&, const vector<byte>&, CIPHER_MODE, PADDING_SCHEME, const vector<byte>&): {EVP_DecryptUpdate} failed.");
		
	}

	if (padding_scheme != NoPadding)
	{
		Padding* padding_function = GetPaadingFunction(padding_scheme);
		padding_function->Unpad(ptext);
	}
	return ptext;
}
