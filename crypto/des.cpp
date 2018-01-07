/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"

#include "iso10126padding.h"
#include "pkcs7padding.h"
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>

#include "des.h"

bool crypto::Des::CheckKey(const vector<byte>& key)
{
	return CheckKeySize(key.size());
}

bool crypto::Des::CheckKeySize(size_t key_size)
{
	switch (key_size)
	{
	case DES:
	case DESede2:
	case DESede3:
		return true;
	default:
		return false;
	}
}

bool crypto::Des::CheckIV(const vector<byte>& iv)
{
	return CheckIVSize(iv.size());
}

bool crypto::Des::CheckIVSize(size_t iv_size)
{
	return iv_size == CryptoPP::DES::BLOCKSIZE;
}

Padding* crypto::Des::GetPaadingFunction(PaddingScheme padding_scheme)
{
	Padding* padding;
	switch (padding_scheme)
	{
	case PKCS5Padding:
		padding = new padding::PKCS5Padding(CryptoPP::DES::BLOCKSIZE);
		break;
	case PKCS7Padding:
		padding = new padding::PKCS7Padding(CryptoPP::DES::BLOCKSIZE);
		break;
	case ISO10126Padding:
		padding = new padding::ISO10126Padding(CryptoPP::DES::BLOCKSIZE);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::GetPaadingFunction(PaddingScheme): {padding_scheme}.");
	}
	return padding;
}

vector<byte> crypto::Des::Encrypt_CBC(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv)
{
	string ctext;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::DES_EDE2>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default: 
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Encrypt_CBC(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(ctext.begin(), ctext.end());
}

vector<byte> crypto::Des::Encrypt_CFB(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv)
{
	string ctext;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::DES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::DES_EDE2>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::DES_EDE3>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Encrypt_CFB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(ctext.begin(), ctext.end());
}

vector<byte> crypto::Des::Encrypt_CTR(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv)
{
	string ctext;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::DES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::DES_EDE2>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::DES_EDE3>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Encrypt_CTR(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(ctext.begin(), ctext.end());
}

vector<byte> crypto::Des::Encrypt_CTS(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv)
{
	string ctext;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_CTS_Mode<CryptoPP::DES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_CTS_Mode<CryptoPP::DES_EDE2>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_CTS_Mode<CryptoPP::DES_EDE3>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Encrypt_CTS(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(ctext.begin(), ctext.end());
}

vector<byte> crypto::Des::Encrypt_ECB(const vector<byte>& padded, const vector<byte>& key)
{
	string ctext;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::DES>::Encryption(key.data(), key.size()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::DES_EDE2>::Encryption(key.data(), key.size()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Encryption(key.data(), key.size()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Encrypt_ECB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(ctext.begin(), ctext.end());
}

vector<byte> crypto::Des::Encrypt_OFB(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv)
{
	string ctext;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::DES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::DES_EDE2>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::DES_EDE3>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(ctext),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Encrypt_OFB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(ctext.begin(), ctext.end());
}

vector<byte> crypto::Des::Decrypt_CBC(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::DES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::DES_EDE2>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Decrypt_CBC(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> crypto::Des::Decrypt_CFB(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::DES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::DES_EDE2>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Decrypt_CFB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> crypto::Des::Decrypt_CTR(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::DES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::DES_EDE2>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Decrypt_CTR(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> crypto::Des::Decrypt_CTS(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_CTS_Mode<CryptoPP::DES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_CTS_Mode<CryptoPP::DES_EDE2>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_CTS_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Decrypt_CTS(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> crypto::Des::Decrypt_ECB(const vector<byte>& ctext, const vector<byte>& key)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::DES>::Decryption(key.data(), key.size()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::DES_EDE2>::Decryption(key.data(), key.size()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Decrypt_ECB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> crypto::Des::Decrypt_OFB(const vector<byte>& ctext, const vector<byte>& key, const vector<byte>& iv)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::DES>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede2:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::DES_EDE2>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	case DESede3:
		CryptoPP::StringSource(
			string(ctext.begin(), ctext.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::Decrypt_OFB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> crypto::Des::random_iv()
{
	vector<byte> iv(CryptoPP::DES::BLOCKSIZE);
	CryptoPP::OS_GenerateRandomBlock(true, iv.data(), iv.size());
	return iv;
}

vector<byte> crypto::Des::default_iv()
{
	return vector<byte>(CryptoPP::DES::BLOCKSIZE, 0);
}

vector<byte> crypto::Des::encrypt(const vector<byte>& ptext, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::encrypt(const vector<byte>&, const vector<byte>& key, CipherMode, PaddingScheme, const vector<byte>&): {key.size()}.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::encrypt(const vector<byte>&, const vector<byte>& key, CipherMode, PaddingScheme, const vector<byte>&): {iv.size()}.");
	}

	vector<byte> padded = ptext;

	if (padding_scheme != NoPadding)
	{
		Padding* padding = GetPaadingFunction(padding_scheme);
		padding->Pad(padded);
		delete padding;
	}

	vector<byte> ctext;
	switch (cipher_mode)
	{
	case CBC:
		ctext = Encrypt_CBC(padded, key, iv);
		break;
	case CFB:
		ctext = Encrypt_CFB(padded, key, iv);
		break;
	case CTR:
		ctext = Encrypt_CTR(padded, key, iv);
		break;
	case CTS:
		ctext = Encrypt_CTS(padded, key, iv);
		break;
	case ECB:
		ctext = Encrypt_ECB(padded, key);
		break;
	case OFB:
		ctext = Encrypt_OFB(padded, key, iv);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::encrypt(const vector<byte>&, const vector<byte>& key, CipherMode, PaddingScheme, const vector<byte>&): {cipher_mode}.");
	}
	return vector<byte>(ctext.begin(), ctext.end());
}

vector<byte> crypto::Des::decrypt(const vector<byte>& ctext, const vector<byte>& key, CipherMode cipher_mode, PaddingScheme padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::decrypt(const vector<byte>&, const vector<byte>& key, CipherMode, PaddingScheme, const vector<byte>&): {key.size()}.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <des.cpp> crypto::Des::decrypt(const vector<byte>&, const vector<byte>& key, CipherMode, PaddingScheme, const vector<byte>&): {iv.size()}.");
	}

	vector<byte> ptext;
	switch (cipher_mode)
	{
	case CBC:
		ptext = Decrypt_CBC(ctext, key, iv);
		break;
	case CFB:
		ptext = Decrypt_CFB(ctext, key, iv);
		break;
	case CTR:
		ptext = Decrypt_CTR(ctext, key, iv);
		break;
	case CTS:
		ptext = Encrypt_CTS(ctext, key, iv);
		break;
	case ECB:
		ptext = Decrypt_ECB(ctext, key);
		break;
	case OFB:
		ptext = Decrypt_OFB(ctext, key, iv);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::decrypt(const vector<byte>&, const vector<byte>&, const CIPHER_MODE&, const PADDING_SCHEME&, const vector<byte>&): {cipher_mode}.");
	}

	vector<byte> message(ptext.begin(), ptext.end());

	if (padding_scheme != NoPadding)
	{
		Padding* padding = GetPaadingFunction(padding_scheme);
		padding->Unpad(message);
		delete padding;
	}
	return message;
}
