#include <algorithm>
#include <vector>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "hex.h"
#include "type.h"
#include "rsa.h"
using std::vector;
using std::string;
using std::exception;

vector<byte> Crypto::Rsa::RSA_encode_PKCS1_OAEP_padding(const vector<byte>& from, const size_t& key_size, const PADDING& padding)
{
	if (!RSA_message_check_length(from, key_size, padding))
	{
		throw exception("message too long");
	}

	vector<byte> hash;
	const EVP_MD* hash_function;
	switch (padding)
	{
	case OAEPwithSHA1andMGF1Padding:
		hash_function = EVP_sha1();
		break;
	case OAEPwithSHA224andMGF1Padding:
		hash_function = EVP_sha224();
		break;
	case OAEPwithSHA256andMGF1Padding:
		hash_function = EVP_sha256();
		break;
	case OAEPwithSHA384andMGF1Padding:
		hash_function = EVP_sha384();
		break;
	case OAEPwithSHA512andMGF1Padding:
		hash_function = EVP_sha512();
		break;

	default:
		throw exception("Padding is not support.");
	}
	vector<byte> buffer(key_size);
	RSA_padding_add_PKCS1_OAEP_mgf1(&buffer[0], buffer.size(), &from[0], from.size(), nullptr, 0, hash_function, nullptr);
	return buffer;
}

vector<byte> Crypto::Rsa::RSA_decode_PKCS1_OAEP_padding(const vector<byte>& from, const PADDING& padding)
{
	size_t hash_size;
	vector<byte> hash;
	const EVP_MD* hash_function;
	switch (padding)
	{
	case OAEPwithSHA1andMGF1Padding:
		hash = Hex::decode("da39a3ee5e6b4b0d3255bfef95601890afd80709");
		hash_size = SHA_DIGEST_LENGTH;
		hash_function = EVP_sha1();
		break;
	case OAEPwithSHA224andMGF1Padding:
		hash = Hex::decode("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
		hash_size = SHA224_DIGEST_LENGTH;
		hash_function = EVP_sha224();
		break;
	case OAEPwithSHA256andMGF1Padding:
		hash = Hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		hash_size = SHA256_DIGEST_LENGTH;
		hash_function = EVP_sha256();
		break;
	case OAEPwithSHA384andMGF1Padding:
		hash = Hex::decode("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
		hash_size = SHA384_DIGEST_LENGTH;
		hash_function = EVP_sha384();
		break;
	case OAEPwithSHA512andMGF1Padding:
		hash = Hex::decode("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
		hash_size = SHA512_DIGEST_LENGTH;
		hash_function = EVP_sha512();
		break;
	default:
		throw exception("Padding is not support.");
	}
	size_t db_size = from.size() - hash_size - 1;
	vector<byte> maskedSeed = vector<byte>(from.begin() + 1, from.begin() + 1 + hash_size);
	vector<byte> maskedDb = vector<byte>(from.begin() + 1 + hash_size, from.end());
	vector<byte> seedMask = vector<byte>(hash_size);
	PKCS1_MGF1(&seedMask[0], hash_size, &maskedDb[0], db_size, hash_function);
	vector<byte> seed = vector<byte>(hash_size);
	for (size_t i = 0; i < hash_size; ++i)
	{
		seed[i] = maskedSeed[i] ^ seedMask[i];
	}
	vector<byte> dbMask = vector<byte>(from.size() - hash_size - 1);
	PKCS1_MGF1(&dbMask[0], db_size, &seed[0], hash_size, hash_function);
	vector<byte> db = vector<byte>(db_size);
	for (size_t i = 0; i < db_size; ++i)
	{
		db[i] = maskedDb[i] ^ dbMask[i];
	}
	vector<byte>::iterator it = find(db.begin() + hash_size, db.end(), '\x1');
	if (it == db.end())
	{
		throw exception("Cannot find 0x01.");
	}
	vector<byte> m(it + 1, db.end());
	vector<byte> lHash(db.begin(), db.begin() + hash_size);

	if (hash != lHash)
	{
		throw exception("The hash value is not correct.");
	}
	return m;
}

bool Crypto::Rsa::RSA_message_check_length(const vector<byte>& data, const size_t& key_size, const PADDING& padding)
{
	return data.size() <= RSA_message_max_length(key_size, padding);
}

size_t Crypto::Rsa::RSA_message_max_length(const size_t& key_size, const PADDING& padding)
{
	size_t max_data_size;
	switch (padding)
	{
	case NoPadding:
		max_data_size = key_size - 1;
		break;
	case PKCS1Padding:
		max_data_size = key_size - RSA_PKCS1_PADDING_SIZE - 1;
		break;
	case OAEPPadding:
	case OAEPwithSHA1andMGF1Padding:
		max_data_size = key_size - 2 * SHA_DIGEST_LENGTH - 2;
		break;
	case OAEPwithSHA224andMGF1Padding:
		max_data_size = key_size - 2 * SHA224_DIGEST_LENGTH - 2;
		break;
	case OAEPwithSHA256andMGF1Padding:
		max_data_size = key_size - 2 * SHA256_DIGEST_LENGTH - 2;
		break;
	case OAEPwithSHA384andMGF1Padding:
		max_data_size = key_size - 2 * SHA384_DIGEST_LENGTH - 2;
		break;
	case OAEPwithSHA512andMGF1Padding:
		max_data_size = key_size - 2 * SHA512_DIGEST_LENGTH - 2;
		break;
	default:
		throw exception("Padding is unsupported.");
	}
	return max_data_size;
}

RSA* Crypto::Rsa::key(const string& key_str, const KEY_TYPE& key_type)
{
	BIO* key_content = BIO_new_mem_buf(key_str.c_str(), key_str.length());
	if (key_content == nullptr)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}

	RSA* rsa_key;
	switch (key_type)
	{
	case PUBLIC_KEY:
		rsa_key = PEM_read_bio_RSA_PUBKEY(key_content, nullptr, nullptr, nullptr);
		break;
	case PRIVATE_KEY:
		rsa_key = PEM_read_bio_RSAPrivateKey(key_content, nullptr, nullptr, nullptr);
		break;
	default:
		throw exception("Key type is unsupported.");
	}
	BIO_free(key_content);
	if (rsa_key == nullptr)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	return rsa_key;
}

vector<byte> Crypto::Rsa::encrypt(const vector<byte>& data, RSA* key, const PADDING& padding, const KEY_TYPE& key_type)
{
	if (RSA_check_key(key) < 0)
	{
		throw exception("RSA key is unsupported.");
	}

	size_t key_size = RSA_size(key);
	if (!RSA_message_check_length(data, key_size, padding))
	{
		throw exception("Message is too long.");
	}

	vector<byte> plain_text_buffer(data.begin(), data.end());
	int PADDING = padding;
	switch (padding)
	{
	case NoPadding:
		plain_text_buffer = vector<byte>(key_size);
		copy(data.begin(), data.end(), plain_text_buffer.begin() + (key_size - data.size()));
		break;
	case PKCS1Padding: break;
	case OAEPPadding: break;
	case OAEPwithSHA1andMGF1Padding:
	case OAEPwithSHA224andMGF1Padding:
	case OAEPwithSHA256andMGF1Padding:
	case OAEPwithSHA384andMGF1Padding:
	case OAEPwithSHA512andMGF1Padding:
		PADDING = RSA_NO_PADDING;
		plain_text_buffer = RSA_encode_PKCS1_OAEP_padding(data, key_size, padding);
		break;
	default:
		throw exception("Padding is unsupported.");
	}
	byte* encrypt_data = new byte[key_size];
	int encrypt_data_length;
	switch (key_type)
	{
	case PUBLIC_KEY:
		encrypt_data_length = RSA_public_encrypt(plain_text_buffer.size(), &plain_text_buffer[0], encrypt_data, key, PADDING);
		break;
	case PRIVATE_KEY:
		encrypt_data_length = RSA_private_encrypt(plain_text_buffer.size(), &plain_text_buffer[0], encrypt_data, key, PADDING);
		break;
	default:
		throw exception("Error key type.");
	}
	if (encrypt_data_length < 0)
	{
		delete[]encrypt_data;
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	vector<byte> encrypt_text(encrypt_data, encrypt_data + encrypt_data_length);
	delete[]encrypt_data;
	return encrypt_text;
}

vector<byte> Crypto::Rsa::decrypt(const vector<byte>& data, RSA* key, const PADDING& padding, const KEY_TYPE& key_type)
{
	size_t rsa_key_size = RSA_size(key);
	byte* plain_data = new byte[rsa_key_size];
	int plain_data_length;

	int PADDING = padding;
	switch (padding)
	{
	case NoPadding: break;
	case PKCS1Padding: break;
	case OAEPPadding: break;
	case OAEPwithSHA1andMGF1Padding:
	case OAEPwithSHA224andMGF1Padding:
	case OAEPwithSHA256andMGF1Padding:
	case OAEPwithSHA384andMGF1Padding:
	case OAEPwithSHA512andMGF1Padding:
		PADDING = RSA_NO_PADDING;
		break;
	default:
		throw exception("Padding is unsupported.");
	}

	switch (key_type)
	{
	case PUBLIC_KEY:
		plain_data_length = RSA_public_decrypt(data.size(), &data[0], plain_data, key, PADDING);
		break;
	case PRIVATE_KEY:
		plain_data_length = RSA_private_decrypt(data.size(), &data[0], plain_data, key, PADDING);
		break;
	default:
		throw exception("Error key type.");
	}
	if (plain_data_length < 0)
	{
		delete[]plain_data;
		ERR_print_errors_fp(stderr);
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	vector<byte> plain_text(plain_data, plain_data + plain_data_length);
	size_t pos = 0;
	switch (padding)
	{
	case NoPadding:
		while (pos < plain_text.size() && plain_text[pos] == 0)
		{
			pos++;
		}
		if (pos < plain_text.size())
		{
			plain_text = vector<byte>(&plain_text[pos], &plain_text[0] + plain_text.size());
		}
		else
		{
			plain_text = vector<byte>();
		}
		break;
	case PKCS1Padding: break;
	case OAEPPadding: break;
	case OAEPwithSHA1andMGF1Padding:
	case OAEPwithSHA224andMGF1Padding:
	case OAEPwithSHA256andMGF1Padding:
	case OAEPwithSHA384andMGF1Padding:
	case OAEPwithSHA512andMGF1Padding:
		plain_text = RSA_decode_PKCS1_OAEP_padding(plain_text, padding);
		break;
	default:
		throw exception("Padding is not supported.");
	}
	delete[]plain_data;
	return plain_text;
}
