/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "aes.h"
#include "iso10126padding.h"
#include "pkcs7padding.h"
#include "pkcs5padding.h"
#include "zeropadding.h"
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

bool Aes::CheckKey(const vector<byte>& key)
{
	return CheckKeySize(key.size());
}

bool Aes::CheckKeySize(const size_t& key_size)
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

bool Aes::CheckIV(const vector<byte>& iv)
{
	return CheckIVSize(iv.size());
}

bool Aes::CheckIVSize(const size_t& iv_size)
{
	return iv_size == CryptoPP::AES::BLOCKSIZE;
}

Padding* Aes::GetPaadingScheme(const PaddingScheme& padding_scheme)
{
	Padding* padding;
	switch (padding_scheme)
	{
	case Zero_Padding:
		padding = new ZeroPadding(CryptoPP::AES::BLOCKSIZE);
		break;
	case PKCS5_Padding:
		padding = new PKCS5Padding(CryptoPP::AES::BLOCKSIZE);
		break;
	case PKCS7_Padding:
		padding = new PKCS7Padding(CryptoPP::AES::BLOCKSIZE);
		break;
	case ISO10126_Padding:
		padding = new ISO10126Padding(CryptoPP::AES::BLOCKSIZE);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::GetPaadingScheme(const PaddingScheme&): {padding_scheme}.");
	}
	return padding;
}

vector<byte> Aes::random_key(const KeySize& key_size)
{
	switch (key_size)
	{
	case AES_128:
	case AES_192:
	case AES_256:
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::random_key(const KeySize&): {key_size}.");
	}
	vector<byte> key = vector<byte>(key_size);
	CryptoPP::OS_GenerateRandomBlock(true, key.data(), key.size());
	return key;
}

vector<byte> Aes::random_iv()
{
	vector<byte> iv(CryptoPP::AES::BLOCKSIZE);
	CryptoPP::OS_GenerateRandomBlock(true, iv.data(), iv.size());
	return iv;
}

vector<byte> Aes::default_iv()
{
	return vector<byte>(CryptoPP::AES::BLOCKSIZE, 0);
}

vector<byte> Aes::encrypt(const vector<byte>& plain, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::encrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {key.size()}.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::encrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {iv.size()}.");
	}

	vector<byte> padded = plain;

	if (padding_scheme != No_Padding)
	{
		Padding* padding = GetPaadingScheme(padding_scheme);
		padding->Pad(padded);
		delete padding;
	}

	CryptoPP::GCM<CryptoPP::AES>::Encryption gcm;
	string cipher;
	switch (cipher_mode)
	{
	case CBC:
	case CTS:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case CFB:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case CTR:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case ECB:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption(key.data(), key.size()),
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case OFB:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::AES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case GCM:
		gcm.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::AuthenticatedEncryptionFilter(
				gcm,
				new CryptoPP::StringSink(cipher)
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::encrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {padding_scheme}.");
	}
	return vector<byte>(cipher.begin(), cipher.end());
}

vector<byte> Aes::decrypt(const vector<byte>& cipher, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::encrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {key.size()}.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::encrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {iv.size()}.");
	}

	string plain;
	CryptoPP::GCM<CryptoPP::AES>::Decryption gcm;
	switch (cipher_mode)
	{
	case CBC:
	case CTS:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case CFB:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case CTR:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case ECB:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption(key.data(), key.size()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case OFB:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case GCM:
		gcm.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::AuthenticatedDecryptionFilter(
				gcm,
				new CryptoPP::StringSink(plain)
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::encrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {cipher_mode}.");
	}

	vector<byte> message(plain.begin(), plain.end());

	if (padding_scheme != No_Padding)
	{
		Padding* padding = GetPaadingScheme(padding_scheme);
		padding->Unpad(message);
		delete padding;
	}
	return message;
}
