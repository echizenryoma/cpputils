#include <vector>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/des.h>
#include "type.h"
#include "des.h"
using std::vector;
using std::string;
using std::exception;

const EVP_CIPHER* Crypto::Des::get_mode(const DES_MODE& mode)
{
	const EVP_CIPHER* cipher_mode;
	switch (mode)
	{
	case CBC:
		cipher_mode = EVP_des_cbc();
		break;
	case CFB:
		cipher_mode = EVP_des_cfb();
		break;
	case ECB:
		cipher_mode = EVP_des_ecb();
		break;
	case OFB:
		cipher_mode = EVP_des_ofb();
		break;
	default:
		throw exception("Mode is unsupported.");
	}
	return cipher_mode;
}


vector<byte> Crypto::Des::key(const string& des_key_str)
{
	DES_cblock key_buffer;
	DES_string_to_key(des_key_str.c_str(), &key_buffer);
	return vector<byte>(key_buffer, key_buffer + DES_KEY_SZ);
}

bool Crypto::Des::check_key(const vector<byte>& des_key)
{
	if (des_key.size() != DES_KEY_SZ)
	{
		return false;
	}
	DES_cblock key_buffer;
	copy(des_key.begin(), des_key.end(), key_buffer);
	return DES_check_key_parity(&key_buffer);
}

vector<byte> Crypto::Des::radom_key()
{
	DES_cblock key_buffer;
	DES_random_key(&key_buffer);
	return vector<byte>(key_buffer, key_buffer + DES_KEY_SZ);
}

vector<byte> Crypto::Des::encrypt(const vector<byte>& data, const vector<byte>& key, const DES_MODE& mode, const DES_PADDING& padding)
{
	int cipher_text_buffer_length = data.size() % DES_KEY_SZ == 0 ? data.size() : (data.size() / DES_KEY_SZ + 1) * DES_KEY_SZ;
	DES_PADDING PADDING = padding;
	vector<byte> message(data);
	switch (padding)
	{
	case NoPadding: break;
	case PKCS5Padding:
		PADDING = PKCS7Padding;
		cipher_text_buffer_length = (data.size() / DES_KEY_SZ + 1) * DES_KEY_SZ;
		if (data.size() % DES_KEY_SZ == 0)
		{
			message.insert(message.end(), DES_KEY_SZ, DES_KEY_SZ);
		}
		break;
	case PKCS7Padding: break;
	case ISO10126Padding: break;
	default:
		throw exception("Padding is unsupported.");
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_CIPHER_CTX_set_padding(ctx, PADDING);
	const EVP_CIPHER* cipher_type = get_mode(mode);

	vector<byte> iv(DES_KEY_SZ);
	int ret = EVP_EncryptInit_ex(ctx, cipher_type, nullptr, &key[0], &iv[0]);
	if (ret <= 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}

	int cipher_text_buffer_written_length = 0;
	vector<byte> cipher_text_buffer(cipher_text_buffer_length);
	ret = EVP_EncryptUpdate(ctx, &cipher_text_buffer[0], &cipher_text_buffer_written_length, &message[0], message.size());
	if (ret <= 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}

	if (cipher_text_buffer_written_length < cipher_text_buffer_length)
	{
		ret = EVP_EncryptFinal_ex(ctx, &cipher_text_buffer[0] + cipher_text_buffer_written_length, &cipher_text_buffer_length);
		if (ret <= 0)
		{
			throw exception(ERR_error_string(ERR_get_error(), nullptr));
		}
	}
	EVP_CIPHER_CTX_cleanup(ctx);

	vector<byte> cipher_text(cipher_text_buffer.begin(), cipher_text_buffer.end());	
	return cipher_text;
}

vector<byte> Crypto::Des::decrypt(const vector<byte>& data, const vector<byte>& key, const DES_MODE& mode, const DES_PADDING& padding)
{
	DES_PADDING PADDING = padding;
	switch (padding)
	{
	case NoPadding: break;
	case PKCS5Padding:
		PADDING = PKCS7Padding;
		break;
	case PKCS7Padding: break;
	case ISO10126Padding: break;
	default:
		throw exception("Padding is unsupported.");
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_CIPHER_CTX_set_padding(ctx, PADDING);
	const EVP_CIPHER* cipher_type = get_mode(mode);

	vector<byte> cipher_text(data);
	vector<byte> iv(DES_KEY_SZ);

	int ret = EVP_DecryptInit_ex(ctx, cipher_type, nullptr, &key[0], &iv[0]);
	if (ret <= 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}

	int plain_text_buffer_length = data.size();
	vector<byte> plain_text_buffer(plain_text_buffer_length);

	int plain_text_buffer_written_length = 0;
	ret = EVP_DecryptUpdate(ctx, &plain_text_buffer[0], &plain_text_buffer_written_length, &data[0], data.size());
	if (ret <= 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	int ex_length = 0;
	ret = EVP_DecryptFinal_ex(ctx, &plain_text_buffer[0] + plain_text_buffer_written_length, &ex_length);
	if (ret <= 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	EVP_CIPHER_CTX_cleanup(ctx);
	plain_text_buffer_written_length += ex_length;
	vector<byte> plain_text(plain_text_buffer.begin(), plain_text_buffer.begin() + plain_text_buffer_written_length);
	return plain_text;
}
