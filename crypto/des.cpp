/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "des.h"
#include "iso10126padding.h"
#include "pkcs7padding.h"
#include "zeropadding.h"
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>

bool Des::CheckKey(const vector<byte>& key)
{
	switch (key.size())
	{
	case DES:
	case DESede2:
	case DESede3:
		return true;
	default:
		return false;
	}
}

bool Des::CheckIV(const vector<byte>& iv)
{
	return iv.size() == CryptoPP::DES::BLOCKSIZE;
}

Padding* Des::GetPaadingScheme(const PaddingScheme& padding_scheme)
{
	Padding* padding;
	switch (padding_scheme)
	{
	case Zero_Padding:
		padding = new ZeroPadding(CryptoPP::DES::BLOCKSIZE);
		break;
	case PKCS5_Padding:
		padding = new PKCS5Padding(CryptoPP::DES::BLOCKSIZE);
		break;
	case PKCS7_Padding:
		padding = new PKCS7Padding(CryptoPP::DES::BLOCKSIZE);
		break;
	case ISO10126_Padding:
		padding = new ISO10126Padding(CryptoPP::DES::BLOCKSIZE);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::GetPaadingScheme(const PaddingScheme&): {padding_scheme}.");
	}
	return padding;
}

vector<byte> Des::Encrypt_CBC(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv)
{
	string cipher;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::DES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default: 
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Encrypt_CBC(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(cipher.begin(), cipher.end());
}

vector<byte> Des::Encrypt_CFB(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv)
{
	string cipher;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::DES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Encrypt_CFB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(cipher.begin(), cipher.end());
}

vector<byte> Des::Encrypt_CTR(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv)
{
	string cipher;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::DES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Encrypt_CTR(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(cipher.begin(), cipher.end());
}

vector<byte> Des::Encrypt_ECB(const vector<byte>& padded, const vector<byte>& key)
{
	string cipher;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::DES>::Encryption(key.data(), key.size()),
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Encrypt_ECB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(cipher.begin(), cipher.end());
}

vector<byte> Des::Encrypt_OFB(const vector<byte>& padded, const vector<byte>& key, const vector<byte>& iv)
{
	string cipher;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(padded.begin(), padded.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::DES>::Encryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
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
				new CryptoPP::StringSink(cipher),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Encrypt_OFB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(cipher.begin(), cipher.end());
}

vector<byte> Des::Decrypt_CBC(const vector<byte>& cipher, const vector<byte>& key, const vector<byte>& iv)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CBC_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Decrypt_CBC(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> Des::Decrypt_CFB(const vector<byte>& cipher, const vector<byte>& key, const vector<byte>& iv)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CFB_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Decrypt_CFB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> Des::Decrypt_CTR(const vector<byte>& cipher, const vector<byte>& key, const vector<byte>& iv)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::CTR_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Decrypt_CTR(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> Des::Decrypt_ECB(const vector<byte>& cipher, const vector<byte>& key)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::ECB_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Decrypt_ECB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> Des::Decrypt_OFB(const vector<byte>& cipher, const vector<byte>& key, const vector<byte>& iv)
{
	string plain;
	switch (key.size())
	{
	case DES:
		CryptoPP::StringSource(
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
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
			string(cipher.begin(), cipher.end()),
			true,
			new CryptoPP::StreamTransformationFilter(
				CryptoPP::OFB_Mode<CryptoPP::DES_EDE3>::Decryption(key.data(), key.size(), iv.data()),
				new CryptoPP::StringSink(plain),
				CryptoPP::StreamTransformationFilter::NO_PADDING
			)
		);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::Decrypt_OFB(const vector<byte>&, const vector<byte>& key, const vector<byte>&): {key.size()}.");;
	}
	return vector<byte>(plain.begin(), plain.end());
}

vector<byte> Des::random_iv()
{
	vector<byte> iv(CryptoPP::DES::BLOCKSIZE);
	CryptoPP::OS_GenerateRandomBlock(true, iv.data(), iv.size());
	return iv;
}

vector<byte> Des::default_iv()
{
	return vector<byte>(CryptoPP::DES::BLOCKSIZE, 0);
}

vector<byte> Des::encrypt(const vector<byte>& plain, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv)
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

	vector<byte> cipher;
	switch (cipher_mode)
	{
	case CBC:
	case CTS:
		cipher = Encrypt_CBC(padded, key, iv);
		break;
	case CFB:
		cipher = Encrypt_CFB(padded, key, iv);
		break;
	case CTR:
		cipher = Encrypt_CTR(padded, key, iv);
		break;
	case ECB:
		cipher = Encrypt_ECB(padded, key);
		break;
	case OFB:
		cipher = Encrypt_OFB(padded, key, iv);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <aes.cpp> Aes::encrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {cipher_mode}.");
	}
	return vector<byte>(cipher.begin(), cipher.end());
}

vector<byte> Des::decrypt(const vector<byte>& cipher, const vector<byte>& key, const CipherMode& cipher_mode, const PaddingScheme& padding_scheme, const vector<byte>& iv)
{
	if (!CheckKey(key))
	{
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::decrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {key.size()}.");
	}

	if (!CheckIV(iv))
	{
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::decrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {iv.size()}.");
	}

	vector<byte> plain;
	switch (cipher_mode)
	{
	case CBC:
	case CTS:
		plain = Decrypt_CBC(cipher, key, iv);
		break;
	case CFB:
		plain = Decrypt_CFB(cipher, key, iv);
		break;
	case CTR:
		plain = Decrypt_CTR(cipher, key, iv);
		break;
	case ECB:
		plain = Decrypt_ECB(cipher, key);
		break;
	case OFB:
		plain = Decrypt_OFB(cipher, key, iv);
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <des.cpp> Des::decrypt(const vector<byte>&, const vector<byte>&, const CipherMode&, const PaddingScheme&, const vector<byte>&): {cipher_mode}.");
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
