/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "padding.h"
using crypto::padding::Padding;

#include "aes.h"
#include "iso10126padding.h"
#include "pkcs7padding.h"
#include "pkcs5padding.h"
#include <cryptopp/aes.h>
#include <cryptopp/gcm.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>

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
	return iv_size == CryptoPP::AES::BLOCKSIZE;
}

Padding* crypto::Aes::GetPaadingFunction(PaddingScheme padding_scheme)
{
	switch (padding_scheme)
	{
	case PKCS5Padding:
		return new padding::PKCS5Padding(CryptoPP::AES::BLOCKSIZE);
	case PKCS7Padding:
		return new padding::PKCS7Padding(CryptoPP::AES::BLOCKSIZE);
	case ISO10126Padding:
		return new padding::ISO10126Padding(CryptoPP::AES::BLOCKSIZE);
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::GetPaadingFunction(PaddingScheme): {padding_scheme}.");
	}
}

vector<byte> crypto::Aes::random_key(KeySize key_size)
{
	switch (key_size)
	{
	case AES_128:
	case AES_192:
	case AES_256:
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::random_key(KeySize): {key_size}.");
	}
	vector<byte> key = vector<byte>(key_size);
	CryptoPP::OS_GenerateRandomBlock(true, key.data(), key.size());
	return key;
}

vector<byte> crypto::Aes::random_iv()
{
	vector<byte> iv(CryptoPP::AES::BLOCKSIZE);
	CryptoPP::OS_GenerateRandomBlock(true, iv.data(), iv.size());
	return iv;
}

vector<byte> crypto::Aes::default_iv()
{
	return vector<byte>(CryptoPP::AES::BLOCKSIZE, 0);
}

vector<byte> crypto::Aes::encrypt(const vector<byte>& ptext, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::encrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {key.size()}.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::encrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {iv.size()}.");
	}

	vector<byte> padded = ptext;

	if (padding_scheme != NoPadding)
	{
		Padding* padding = GetPaadingFunction(padding_scheme);
		padding->Pad(padded);
		delete padding;
	}

	CryptoPP::GCM<CryptoPP::AES>::Encryption gcm;
	string cipher;
	switch (cipher_mode)
	{
	case CBC:
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
	case CTS:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_CTS_Mode<CryptoPP::AES>::Encryption(key.data(), key.size(), iv.data()),
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

vector<byte> crypto::Aes::decrypt(const vector<byte>& ctext, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::decrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {key.size()}.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::decrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {iv.size()}.");
	}

	string ptext;
	CryptoPP::GCM<CryptoPP::AES>::Decryption gcm;
	switch (cipher_mode)
	{
	case CBC:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ptext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case CFB:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ptext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case CTR:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ptext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case CTS:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_CTS_Mode<CryptoPP::AES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ptext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case ECB:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption(key.data(), key.size()),
				new CryptoPP::StringSink(ptext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case OFB:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::AES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ptext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case GCM:
		gcm.SetKeyWithIV(key.data(), key.size(), iv.data(), iv.size());
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::AuthenticatedDecryptionFilter(
				gcm,
				new CryptoPP::StringSink(ptext)
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> crypto::Aes::decrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {cipher_mode}.");
	}

	vector<byte> out(ptext.begin(), ptext.end());

	if (padding_scheme != NoPadding)
	{
		Padding* padding = GetPaadingFunction(padding_scheme);
		padding->Unpad(out);
		delete padding;
	}
	return out;
}
