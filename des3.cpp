#include <vector>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/des.h>
#include "type.h"
#include "des3.h"
using std::vector;
using std::string;
using std::exception;

const EVP_CIPHER* Crypto::Des3::get_mode(const DES3_MODE& mode, const size_t& key_count)
{
	if (key_count != 2 && key_count != 3)
	{
		throw exception("The key_count is unsupported.");
	}

	const EVP_CIPHER* cipher_mode;
	switch (mode)
	{
	case CBC:
		cipher_mode = key_count == 2 ? EVP_des_ede_cbc() : EVP_des_ede3_cbc();
		break;
	case CFB:
		cipher_mode = key_count == 2 ? EVP_des_ede_cfb() : EVP_des_ede3_cfb();
		break;
	case ECB:
		cipher_mode = key_count == 2 ? EVP_des_ede_ecb() : EVP_des_ede3_ecb();
		break;
	case OFB:
		cipher_mode = key_count == 2 ? EVP_des_ede_ofb() : EVP_des_ede3_ofb();
		break;
	default:
		throw exception("The mode is unsupported.");
	}
	return cipher_mode;
}

bool Crypto::Des3::check_key(const vector<byte>& des_key)
{
	if (des_key.size() != 2 * DES_KEY_SZ && des_key.size() != 3 * DES_KEY_SZ)
	{
		return false;
	}

	for (size_t i = 0; i < des_key.size() / DES_KEY_SZ; ++i)
	{
		DES_cblock key_buffer;
		copy(des_key.begin() + i * DES_KEY_SZ, des_key.begin() + (i + 1) * DES_KEY_SZ, key_buffer);
		if (!DES_check_key_parity(&key_buffer))
		{
			return false;
		}
	}
	return true;
}

vector<byte> Crypto::Des3::radom_key(const size_t& key_count)
{
	vector<byte> key;
	DES_cblock key_buffer;

	for (size_t i = 0; i < key_count; ++i)
	{
		DES_random_key(&key_buffer);
		key.insert(key.end(), &key_buffer[0], &key_buffer[DES_KEY_SZ]);
	}
	return key;
}

vector<byte> Crypto::Des3::encrypt(const vector<byte>& data, const vector<byte>& key, const DES3_MODE& mode, const DES3_PADDING& padding)
{
	if (!check_key(key))
	{
		throw exception("The key is unsupported.");
	}

	int cipher_text_buffer_length = (data.size() / DES_KEY_SZ + 1) * DES_KEY_SZ;
	vector<byte> message(data);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_CIPHER_CTX_set_padding(ctx, padding);
	const EVP_CIPHER* cipher_type = get_mode(mode, key.size() / DES_KEY_SZ);

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

	int ex_length = 0;
	ret = EVP_EncryptFinal_ex(ctx, &cipher_text_buffer[0] + cipher_text_buffer_written_length, &ex_length);
	if (ret <= 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	cipher_text_buffer_written_length += ex_length;
	EVP_CIPHER_CTX_cleanup(ctx);
	vector<byte> cipher_text(cipher_text_buffer.begin(), cipher_text_buffer.begin() + cipher_text_buffer_written_length);
	return cipher_text;
}

vector<byte> Crypto::Des3::decrypt(const vector<byte>& data, const vector<byte>& key, const DES3_MODE& mode, const DES3_PADDING& padding)
{
	if (!check_key(key))
	{
		throw exception("The key is unsupported.");
	}

	if (data.size() % DES_KEY_SZ != 0)
	{
		throw exception("The length of cipher-text is error.");
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_CIPHER_CTX_set_padding(ctx, padding);
	const EVP_CIPHER* cipher_type = get_mode(mode, key.size() / DES_KEY_SZ);

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
