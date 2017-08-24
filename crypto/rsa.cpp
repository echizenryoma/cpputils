/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "rsa.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "pkcs5padding.h"
#include "nopadding.h"
#include "pkcs7padding.h"
#include "oaepping.h"

using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

//vector<byte> crypto::Rsa::PEM2DER(const string& pem_key_str, bool private_key)
//{
//	vector<byte> der;
//
//	BIO_ptr bio(BIO_new_mem_buf(pem_key_str.c_str(), pem_key_str.size()), BIO_free);
//	if (bio.get() == nullptr)
//	{
//		throw std::bad_alloc();
//	}
//
//	if (private_key)
//	{
//		EVP_KEY_ptr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
//		if (key.get() == nullptr)
//		{
//			throw std::runtime_error("[invalid_argument] <rsa.cpp> crypto::Rsa::PEM2DER(const string&, bool): {PEM_read_bio_PrivateKey} failed.");
//		}
//
//		RSA_ptr rsa(EVP_PKEY_get1_RSA(key.get()), RSA_free);
//		if (rsa.get() == nullptr)
//		{
//			throw std::runtime_error("[invalid_argument] <rsa.cpp> crypto::Rsa::PEM2DER(const string&, bool): {EVP_PKEY_get1_RSA} failed.");
//		}
//
//		BIO_ptr der_bio(BIO_new(BIO_s_mem()), BIO_free);
//		if (der_bio.get() == nullptr)
//		{
//			throw std::bad_alloc();
//		}
//
//		int rc = i2d_RSAPrivateKey_bio(der_bio.get(), rsa.get());
//		if (rc != 1)
//		{
//			throw std::runtime_error("[invalid_argument] <rsa.cpp> crypto::Rsa::PEM2DER(const string&, bool): {i2d_RSAPrivateKey_bio} failed.");
//		}
//
//		BUF_MEM* buf_mem;
//		BIO_flush(der_bio.get());
//		BIO_get_mem_ptr(der_bio.get(), &buf_mem);
//		BIO_set_close(der_bio.get(), BIO_NOCLOSE);
//		if (buf_mem == nullptr)
//		{
//			throw std::bad_alloc();
//		}
//		der = vector<byte>(buf_mem->data, buf_mem->data + buf_mem->length);
//		BUF_MEM_free(buf_mem);
//	}
//	else
//	{
//		EVP_KEY_ptr key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
//		if (key.get() == nullptr)
//		{
//			throw std::runtime_error("[invalid_argument] <rsa.cpp> crypto::Rsa::PEM2DER(const string&, bool): {PEM_read_bio_PrivateKey} failed.");
//		}
//
//		RSA_ptr rsa(EVP_PKEY_get1_RSA(key.get()), RSA_free);
//		if (rsa.get() == nullptr)
//		{
//			throw std::runtime_error("[invalid_argument] <rsa.cpp> crypto::Rsa::PEM2DER(const string&, bool): {EVP_PKEY_get1_RSA} failed.");
//		}
//
//		BIO_ptr der_bio(BIO_new(BIO_s_mem()), BIO_free);
//		if (der_bio.get() == nullptr)
//		{
//			throw std::bad_alloc();
//		}
//
//		int rc = i2d_RSAPublicKey_bio(der_bio.get(), rsa.get());
//		if (rc != 1)
//		{
//			throw std::runtime_error("[invalid_argument] <rsa.cpp> crypto::Rsa::PEM2DER(const string&, bool): {i2d_RSAPublicKey_bio} failed.");
//		}
//
//		BIO_flush(der_bio.get());
//		BUF_MEM* buf_mem;
//		BIO_get_mem_ptr(der_bio.get(), &buf_mem);
//		BIO_set_close(der_bio.get(), BIO_NOCLOSE);
//		if (buf_mem == nullptr)
//		{
//			throw std::bad_alloc();
//		}
//		der = vector<byte>(buf_mem->data, buf_mem->data + buf_mem->length);
//		BUF_MEM_free(buf_mem);
//	}
//	return der;
//}

Padding* crypto::Rsa::GetPaadingFunction(PaddingScheme padding_scheme, size_t key_size)
{
	Padding* padding;
	switch (padding_scheme)
	{
	case NoPadding:
		padding = new padding::NoPadding(key_size);
		break;
	case PKCS5Padding:
		padding = new padding::PKCS5Padding(key_size);
		break;
	case PKCS7Padding:
		padding = new padding::PKCS7Padding(key_size);
		break;
	case OAEPwithSHA1andMGF1Padding:
		padding = new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA1);
		break;
	case OAEPwithSHA224andMGF1Padding:
		padding = new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA224);
		break;
	case OAEPwithSHA256andMGF1Padding:
		padding = new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA256);
		break;
	case OAEPwithSHA384andMGF1Padding:
		padding = new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA384);
		break;
	case OAEPwithSHA512andMGF1Padding:
		padding = new padding::OAEPwithHashandMGF1Padding(key_size, padding::OAEPwithHashandMGF1Padding::SHA512);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Rsa::GetPaadingFunction(PaddingScheme, size_t): {padding_scheme} is not support.");
	}
	return padding;
}

int crypto::Rsa::GetMaxMessageSize(PaddingScheme padding_scheme, size_t key_size)
{
	int max_msg_size = 0;

	Padding* padding = nullptr;
	switch (padding_scheme)
	{
	case NoPadding:
		max_msg_size = key_size;
		break;
	case PKCS5Padding:
	case PKCS7Padding:
		max_msg_size = key_size - 1;
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
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Rsa::GetMaxMessageSize(PaddingScheme, size_t): {padding_scheme} is not support.");
	}
	return max_msg_size;
}

bool crypto::Rsa::CheckMessageSize(PaddingScheme padding_scheme, size_t key_size, size_t msg_size)
{
	return msg_size > static_cast<size_t>(GetMaxMessageSize(padding_scheme, key_size));
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

vector<byte> crypto::Rsa::encrypt(const vector<byte>& msg, RSA* key, PaddingScheme padding_scheme, KeyType key_type)
{
	if (RSA_check_key(key) < 0)
	{
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {key_type} is not support.");
	}

	size_t key_size = RSA_size(key);
	if (!CheckMessageSize(padding_scheme, key_size, msg.size()))
	{
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {msg} is too long.");
	}

	vector<byte> padded = msg;
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

vector<byte> crypto::Rsa::decrypt(const vector<byte>& ctext, RSA* key, PaddingScheme padding_scheme, KeyType key_type)
{
	if (RSA_check_key(key) < 0)
	{
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::decrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {key_type} is not support.");
	}
	size_t key_size = RSA_size(key);

	if (!CheckMessageSize(padding_scheme, key_size, ctext.size()))
	{
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::decrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {ctext} is too long.");
	}

	vector<byte> ptext(key_size);
	int ptext_size;
	switch (key_type)
	{
	case PublicKey:
		ptext_size = RSA_public_encrypt(ctext.size(), ctext.data(), ptext.data(), key, RSA_NO_PADDING);
		break;
	case PrivateKey:
		ptext_size = RSA_private_encrypt(ctext.size(), ctext.data(), ptext.data(), key, RSA_NO_PADDING);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType): {key_type} is not support.");
	}
	if (ptext_size < 0)
	{
		throw std::runtime_error("[runtime_error] <rsa.cpp> crypto::Rsa::encrypt(const vector<byte>&, RSA*, PaddingScheme, KeyType):" + string(ERR_error_string(ERR_get_error(), nullptr)));
	}

	vector<byte> msg = ptext;
	Padding* padding = GetPaadingFunction(padding_scheme, key_size);
	padding->Pad(msg);
	delete padding;

	return msg;
}

//CryptoPP::RSA::PublicKey crypto::Rsa::pubkey(const string& key_str)
//{
//	vector<byte> key_der = PEM2DER(key_str, false);
//
//	CryptoPP::StringSource key_source(string(key_der.begin(), key_der.end()), true);
//	CryptoPP::ByteQueue key_bytes;
//	key_source.TransferTo(key_bytes);
//	key_bytes.MessageEnd();
//
//	CryptoPP::RSA::PublicKey public_key;
//	public_key.BERDecodePublicKey(key_bytes, false, static_cast<size_t>(key_bytes.MaxRetrievable()));
//	return public_key;
//}
//
//CryptoPP::RSA::PrivateKey crypto::Rsa::privkey(const string& key_str)
//{
//	vector<byte> key_der = PEM2DER(key_str, true);
//
//	CryptoPP::StringSource key_source(string(key_der.begin(), key_der.end()), true);
//	CryptoPP::ByteQueue key_bytes;
//	key_source.TransferTo(key_bytes);
//	key_bytes.MessageEnd();
//
//	CryptoPP::RSA::PrivateKey private_key;
//	private_key.BERDecodePrivateKey(key_bytes, false, static_cast<size_t>(key_bytes.MaxRetrievable()));
//	return private_key;
//}
