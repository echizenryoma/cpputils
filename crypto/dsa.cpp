#include "pch.h"

#include "dsa.h"
using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using EVP_KEY_ptr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

DSA_ptr crypto::signature::Dsa::pubkey(const string& pem_key_str)
{
	if (pem_key_str.size() > INT_MAX)
	{
		throw std::length_error("[length_error] <rsa.cpp> crypto::signature::Dsa::pubkey(const string&): {pem_key_str} is too long.");
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
	return DSA_ptr(EVP_PKEY_get1_DSA(key.get()), DSA_free);
}

DSA_ptr crypto::signature::Dsa::privkey(const string& pem_key_str)
{
	if (pem_key_str.size() > INT_MAX)
	{
		throw std::length_error("[length_error] <rsa.cpp> crypto::signature::Dsa::privkey(const string&): {pem_key_str} is too long.");
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
	return DSA_ptr(EVP_PKEY_get1_DSA(key.get()), DSA_free);
}

vector<byte> crypto::signature::Dsa::sign(const DSA_ptr& private_key, const vector<byte>& hash)
{
	const unsigned key_size = DSA_size(private_key.get());
	if (hash.size() > INT_MAX)
	{
		throw std::invalid_argument("[invalid_argument] <dsa.cpp> crypto::signature::Dsa::sign(const DSA_ptr&, const vector<byte>&): {hash} is too long.");
	}

	unsigned slen = key_size;
	vector<byte> stext(slen);
	if (!DSA_sign(NID_undef, hash.data(), static_cast<int>(hash.size()), stext.data(), &slen, private_key.get()))
	{
		throw std::runtime_error("[runtime_error] <dsa.cpp> crypto::signature::Dsa::sign(const DSA_ptr&, const vector<byte>&):" + string(ERR_error_string(ERR_get_error(), nullptr)));
	}
	stext.resize(slen);
	return stext;
}

bool crypto::signature::Dsa::verify(const DSA_ptr& public_key, const vector<byte>& stext, const vector<byte>& hash)
{
	const size_t key_size = DSA_size(public_key.get());
	if (hash.size() > INT_MAX || stext.size() > INT_MAX)
	{
		return false;
	}
	return DSA_verify(NID_undef, hash.data(), static_cast<int>(hash.size()), stext.data(), static_cast<int>(stext.size()), public_key.get());
}
