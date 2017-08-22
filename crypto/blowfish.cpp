/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "blowfish.h"
#include "pkcs7padding.h"
#include "iso10126padding.h"
#include "zeropadding.h"
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>

bool crypto::Blowfish::CheckKey(const vector<byte>& key)
{
	return CheckKeySize(key.size());
}

bool crypto::Blowfish::CheckKeySize(size_t key_size)
{
	return key_size >= CryptoPP::Blowfish::MIN_KEYLENGTH && key_size <= CryptoPP::Blowfish::MAX_KEYLENGTH;
}

bool crypto::Blowfish::CheckIV(const vector<byte>& iv)
{
	return CheckIVSize(iv.size());
}

bool crypto::Blowfish::CheckIVSize(size_t iv_size)
{
	return iv_size == CryptoPP::Blowfish::BLOCKSIZE;
}

Padding* crypto::Blowfish::GetPaadingFunction(PaddingScheme padding_scheme)
{
	Padding* padding;
	switch (padding_scheme)
	{
	case ZeroPadding:
		padding = new padding::ZeroPadding(CryptoPP::Blowfish::BLOCKSIZE);
		break;
	case PKCS5Padding:
		padding = new padding::PKCS5Padding(CryptoPP::Blowfish::BLOCKSIZE);
		break;
	case PKCS7Padding:
		padding = new padding::PKCS7Padding(CryptoPP::Blowfish::BLOCKSIZE);
		break;
	case ISO10126Padding:
		padding = new padding::ISO10126Padding(CryptoPP::Blowfish::BLOCKSIZE);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <blowfish.cpp> crypto::Blowfish::GetPaadingFunction(PaddingScheme): {padding_scheme}.");
	}
	return padding;
}

vector<byte> crypto::Blowfish::random_key(size_t key_size)
{
	if (!CheckKeySize(key_size))
	{
		throw std::invalid_argument("[invalid_argument] <blowfish.cpp> crypto::Blowfish::random_key(size_t): {key_size}.");
	}

	vector<byte> key(key_size);
	CryptoPP::OS_GenerateRandomBlock(true, key.data(), key.size());
	return key;
}

vector<byte> crypto::Blowfish::random_iv()
{
	vector<byte> iv(CryptoPP::Blowfish::BLOCKSIZE);
	CryptoPP::OS_GenerateRandomBlock(true, iv.data(), iv.size());
	return iv;
}

vector<byte> crypto::Blowfish::default_iv()
{
	return vector<byte>(CryptoPP::Blowfish::BLOCKSIZE, 0);
}

vector<byte> crypto::Blowfish::encrypt(const vector<byte>& ptext, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <blowfish.cpp> crypto::Blowfish::encrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {key.size()}.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <blowfish.cpp> crypto::Blowfish::encrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {iv.size()}.");
	}

	vector<byte> padded = ptext;

	if (padding_scheme != NoPadding)
	{
		Padding* padding = GetPaadingFunction(padding_scheme);
		padding->Pad(padded);
		delete padding;
	}
	string cipher;

	switch (cipher_mode)
	{
	case CBC:
	case CTS:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Encryption(key.data(), key.size(), iv.data()),
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
				CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Encryption(key.data(), key.size(), iv.data()),
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
				CryptoPP::CTR_Mode<CryptoPP::Blowfish>::Encryption(key.data(), key.size(), iv.data()),
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
				CryptoPP::ECB_Mode<CryptoPP::Blowfish>::Encryption(key.data(), key.size()),
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
				CryptoPP::OFB_Mode<CryptoPP::Blowfish>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <blowfish.cpp> crypto::Blowfish::encrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {padding_scheme}.");
	}
	return vector<byte>(cipher.begin(), cipher.end());
}

vector<byte> crypto::Blowfish::decrypt(const vector<byte>& cipher, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <blowfish.cpp> crypto::Blowfish::decrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {key.size()}.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <blowfish.cpp> crypto::Blowfish::decrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {iv.size()}.");
	}

	string plain;
	switch (cipher_mode)
	{
	case CBC:
	case CTS:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::Blowfish>::Decryption(key.data(), key.size(), iv.data()),
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
				CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Decryption(key.data(), key.size(), iv.data()),
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
				CryptoPP::CTR_Mode<CryptoPP::Blowfish>::Decryption(key.data(), key.size(), iv.data()),
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
				CryptoPP::ECB_Mode<CryptoPP::Blowfish>::Decryption(key.data(), key.size()),
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
				CryptoPP::OFB_Mode<CryptoPP::Blowfish>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <blowfish.cpp> crypto::Blowfish::decrypt(const vector<byte>&, const vector<byte>&, CipherMode, PaddingScheme, const vector<byte>&): {cipher_mode}.");
	}

	vector<byte> message(plain.begin(), plain.end());

	if (padding_scheme != NoPadding)
	{
		Padding* padding = GetPaadingFunction(padding_scheme);
		padding->Unpad(message);
		delete padding;
	}
	return message;
}
