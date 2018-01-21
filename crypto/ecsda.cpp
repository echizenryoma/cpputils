#include "pch.h"

#include "ecdsa.h"
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;

EC_KEY_ptr crypto::signature::EcDsa::pubkey(const string& pem_key_str)
{
	if (pem_key_str.size() > INT_MAX)
	{
		throw std::length_error("[length_error] <ecdsa.cpp> crypto::signature::EcDsa::pubkey(const string&): {pem_key_str} is too long.");
	}

	BIO_ptr bio(BIO_new_mem_buf(pem_key_str.data(), static_cast<int>(pem_key_str.size())), BIO_free);
	if (bio.get() == nullptr)
	{
		throw std::bad_alloc();
	}
	EVP_KEY_ptr key(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (key.get() == nullptr)
	{
		throw std::bad_alloc();
	}
	return EC_KEY_ptr(EVP_PKEY_get1_EC_KEY(key.get()), EC_KEY_free);
}


EVP_KEY_ptr crypto::signature::EcDsa::privkey(const string& pem_key_str)
{
	if (pem_key_str.size() > INT_MAX)
	{
		throw std::length_error("[length_error] <ecdsa.cpp> crypto::signature::EcDsa::privkey(const string&): {pem_key_str} is too long.");
	}

	BIO_ptr bio(BIO_new_mem_buf(pem_key_str.data(), static_cast<int>(pem_key_str.size())), BIO_free);
	if (bio.get() == nullptr)
	{
		throw std::bad_alloc();
	}
	EVP_KEY_ptr key(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
	if (key.get() == nullptr)
	{
		throw std::bad_alloc();
	}
	return key;
}

vector<byte> crypto::signature::EcDsa::sign(const EVP_KEY_ptr& private_key, const vector<byte>& hash)
{
	if (hash.size() > INT_MAX)
	{
		throw std::invalid_argument("[invalid_argument] <dsa.cpp> crypto::signature::Dsa::sign(const EVP_KEY_ptr&, const vector<byte>&): {hash} is too long.");
	}

	const unsigned key_size = EVP_PKEY_size(private_key.get());
	unsigned slen = key_size;
	vector<byte> stext(slen);
	if (!ECDSA_sign(NID_undef, hash.data(), static_cast<int>(hash.size()), stext.data(), &slen, EC_KEY_ptr(EVP_PKEY_get1_EC_KEY(private_key.get()), EC_KEY_free).get()))
	{
		throw std::runtime_error("[runtime_error] <dsa.cpp> crypto::signature::Dsa::sign(const EVP_KEY_ptr&, const vector<byte>&):" + string(ERR_error_string(ERR_get_error(), nullptr)));
	}
	stext.resize(slen);
	return stext;
}

bool crypto::signature::EcDsa::verify(const EC_KEY_ptr& public_key, const vector<byte>& stext, const vector<byte>& hash)
{
	if (hash.size() > INT_MAX || stext.size() > INT_MAX)
	{
		return false;
	}
	return ECDSA_verify(NID_undef, hash.data(), static_cast<int>(hash.size()), stext.data(), static_cast<int>(stext.size()), public_key.get());
}
