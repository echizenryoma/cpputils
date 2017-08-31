/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "rsa.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "nopadding.h"
#include "oaepping.h"
#include "pkcs1padding.h"

using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

Padding* crypto::Rsa::GetPaadingFunction(PaddingScheme padding_scheme, size_t key_size, KeyType key_type, const vector<byte>& label)
{
	Padding* padding;
	switch (padding_scheme)
	{
	case NoPadding:
		return new padding::NoPadding(key_size);
	case PKCS1Padding:
		switch (key_type)
		{
		case PublicKey:
			return new padding::PKCS1v15Padding(key_size, padding::PKCS1v15Padding::PUBLIC_KEY_OPERATION);
		case PrivateKey:
			return new padding::PKCS1v15Padding(key_size, padding::PKCS1v15Padding::PRIVATE_KEY_OPERATION);
		default:
			throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::GetPaadingFunction(PaddingScheme, size_t, KeyType, const vector<byte>&): {key_type} is not support.");
		}
	case OAEPwithSHA1andMGF1Padding:
		return new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA1, label);
	case OAEPwithSHA224andMGF1Padding:
		return new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA224, label);
	case OAEPwithSHA256andMGF1Padding:
		return new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA256, label);
	case OAEPwithSHA384andMGF1Padding:
		return new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA384, label);
	case OAEPwithSHA512andMGF1Padding:
		return new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA512, label);
	default:
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::GetPaadingFunction(PaddingScheme, size_t, KeyType, const vector<byte>&): {padding_scheme} is not support.");
	}
}

int crypto::Rsa::GetMaxMessageSize(PaddingScheme padding_scheme, size_t key_size)
{
	int max_msg_size;

	Padding* padding;
	switch (padding_scheme)
	{
	case NoPadding:
		max_msg_size = key_size;
		break;
	case PKCS1Padding:
		padding = new padding::PKCS1v15Padding(key_size);
		max_msg_size = padding->GetPadLength(0);
		delete padding;
		break;
	case OAEPwithSHA1andMGF1Padding:
	case OAEPwithSHA224andMGF1Padding:
	case OAEPwithSHA256andMGF1Padding:
	case OAEPwithSHA384andMGF1Padding:
	case OAEPwithSHA512andMGF1Padding:
		padding = GetPaadingFunction(padding_scheme, key_size);
		max_msg_size = padding->GetPadLength(0) - 1;
		delete padding;
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::GetMaxMessageSize(PaddingScheme, size_t): {padding_scheme} is not support.");
	}
	return max_msg_size;
}

bool crypto::Rsa::CheckMessageSize(PaddingScheme padding_scheme, size_t key_size, size_t msg_size)
{
	return msg_size <= static_cast<size_t>(GetMaxMessageSize(padding_scheme, key_size));
}


RSA_ptr crypto::Rsa::pubkey(const string& pem_key_str)
{
	BIO_ptr bio(BIO_new_mem_buf(pem_key_str.c_str(), pem_key_str.size()), BIO_free);
	if (bio.get() == nullptr)
	{
		throw std::bad_alloc();
	}
	EVP_KEY_ptr key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (key.get() == nullptr)
	{
		throw std::runtime_error("[runtime_error] <rsa.cpp> crypto::Rsa::PEM2DER(const string&, bool): {PEM_read_bio_PrivateKey} failed.");
	}
	RSA_ptr rsa(EVP_PKEY_get1_RSA(key.get()), RSA_free);
	return rsa;
}

RSA_ptr crypto::Rsa::privkey(const string& pem_key_str)
{
	BIO_ptr bio(BIO_new_mem_buf(pem_key_str.c_str(), pem_key_str.size()), BIO_free);
	if (bio.get() == nullptr)
	{
		throw std::bad_alloc();
	}
	EVP_KEY_ptr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (key.get() == nullptr)
	{
		throw std::runtime_error("[runtime_error] <rsa.cpp> crypto::Rsa::PEM2DER(const string&, bool): {PEM_read_bio_PrivateKey} failed.");
	}
	RSA_ptr rsa(EVP_PKEY_get1_RSA(key.get()), RSA_free);
	return rsa;
}

RSA_ptr crypto::Rsa::key(const string& pem_key_str, KeyType key_type)
{
	switch (key_type)
	{
	case PublicKey:
		return pubkey(pem_key_str);
	case PrivateKey:
		return privkey(pem_key_str);
	default:
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::key(const string&, KeyType): {key_type} is not support.");
	}
}

vector<byte> crypto::Rsa::encrypt(const vector<byte>& ptext, RSA* key, KeyType key_type, PaddingScheme padding_scheme, const vector<byte>& label)
{
	if (RSA_check_key(key) < 0)
	{
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {key_type} is not support.");
	}

	size_t key_size = RSA_size(key);
	if (!CheckMessageSize(padding_scheme, key_size, ptext.size()))
	{
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {msg} is too long.");
	}

	vector<byte> padded = ptext;
	Padding* padding = GetPaadingFunction(padding_scheme, key_size);
	padding->Pad(padded);
	delete padding;

	vector<byte> ctext(key_size);
	int ctext_size;
	switch (key_type)
	{
	case PublicKey:
		ctext_size = RSA_public_encrypt(padded.size(), padded.data(), ctext.data(), key, RSA_NO_PADDING);
		break;
	case PrivateKey:
		ctext_size = RSA_private_encrypt(padded.size(), padded.data(), ctext.data(), key, RSA_NO_PADDING);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {key_type} is not support.");
	}
	if (ctext_size < 0)
	{
		throw std::runtime_error("[runtime_error] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType):" + string(ERR_error_string(ERR_get_error(), nullptr)));
	}
	ctext.resize(ctext_size);
	return ctext;
}

vector<byte> crypto::Rsa::decrypt(const vector<byte>& ctext, RSA* key, KeyType key_type, PaddingScheme padding_scheme, const vector<byte>& label)
{
	if (RSA_check_key(key) < 0)
	{
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::decrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {key_type} is not support.");
	}
	size_t key_size = RSA_size(key);

	vector<byte> ptext(key_size);
	int ptext_size;
	switch (key_type)
	{
	case PublicKey:
		ptext_size = RSA_public_decrypt(ctext.size(), ctext.data(), ptext.data(), key, RSA_NO_PADDING);
		break;
	case PrivateKey:
		ptext_size = RSA_private_decrypt(ctext.size(), ctext.data(), ptext.data(), key, RSA_NO_PADDING);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {key_type} is not support.");
	}
	if (ptext_size < 0)
	{
		throw std::runtime_error("[runtime_error] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType):" + string(ERR_error_string(ERR_get_error(), nullptr)));
	}
	ptext.resize(ptext_size);

	vector<byte> msg = ptext;
	Padding* padding = GetPaadingFunction(padding_scheme, key_size);
	padding->Unpad(msg);
	delete padding;
	return msg;
}
