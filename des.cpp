#include <vector>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/rand.h>
#include "type.h"
#include "des.h"
using std::vector;
using std::string;
using std::exception;

const EVP_CIPHER* Crypto::Des::get_mode(const MODE& mode, const size_t& key_size)
{
	if (!check_key_size(key_size))
	{
		throw exception("The key size is unsupported.");
	}

	const EVP_CIPHER* cipher_mode;
	switch (mode)
	{
	case CBC:
		switch (key_size)
		{
		case DES:
			cipher_mode = EVP_des_cbc();
			break;
		case DES_EDE:
			cipher_mode = EVP_des_ede_cbc();
			break;
		case DES_EDE3:
			cipher_mode = EVP_des_ede3_cbc();
			break;
		default:
			throw exception("The key size is unsupported.");
		}
		break;
	case CFB:
		switch (key_size)
		{
		case DES:
			cipher_mode = EVP_des_cfb();
			break;
		case DES_EDE:
			cipher_mode = EVP_des_ede_cfb();
			break;
		case DES_EDE3:
			cipher_mode = EVP_des_ede3_cfb();
			break;
		default:
			throw exception("The key size is unsupported.");
		}
		break;
	case ECB:
		switch (key_size)
		{
		case DES:
			cipher_mode = EVP_des_ecb();
			break;
		case DES_EDE:
			cipher_mode = EVP_des_ede_ecb();
			break;
		case DES_EDE3:
			cipher_mode = EVP_des_ede3_ecb();
			break;
		default:
			throw exception("The key size is unsupported.");
		}
		break;
	case OFB:
		switch (key_size)
		{
		case DES:
			cipher_mode = EVP_des_ofb();
			break;
		case DES_EDE:
			cipher_mode = EVP_des_ede_ofb();
			break;
		case DES_EDE3:
			cipher_mode = EVP_des_ede3_ofb();
			break;
		default:
			throw exception("The key size is unsupported.");
		}
		break;
	default:
		throw exception("The mode is unsupported.");
	}
	return cipher_mode;
}

bool Crypto::Des::check_cipher_text(const vector<byte>& cipher_text)
{
	return cipher_text.size() % DES_KEY_SZ == 0;
}

bool Crypto::Des::check_key(const vector<byte>& key)
{
	if (!check_key_size(key.size()))
	{
		return false;
	}

	for (size_t i = 0; i < key.size() / DES_KEY_SZ; ++i)
	{
		DES_cblock key_buffer;
		copy(key.begin() + i * DES_KEY_SZ, key.begin() + (i + 1) * DES_KEY_SZ, key_buffer);
		if (!DES_check_key_parity(&key_buffer))
		{
			return false;
		}
	}
	return true;
}

bool Crypto::Des::check_key_size(const size_t& key_size)
{
	switch (key_size)
	{
	case DES:
	case DES_EDE:
	case DES_EDE3:
		return true;
	default:
		return false;
	}
}

vector<byte> Crypto::Des::radom_key(const MOTHED& key_mothed)
{
	if (!check_key_size(key_mothed))
	{
		throw exception("The key mothed is unsupported.");
	}

	vector<byte> key;
	DES_cblock key_buffer;
	for (size_t i = 0; i < key_mothed / DES_KEY_SZ; ++i)
	{
		DES_random_key(&key_buffer);
		key.insert(key.end(), &key_buffer[0], &key_buffer[DES_KEY_SZ]);
	}
	return key;
}

bool Crypto::Des::check_iv(const vector<byte>& iv)
{
	return iv.size() == DES_KEY_SZ;
}

vector<byte> Crypto::Des::radom_iv()
{
	vector<byte> iv(DES_KEY_SZ);
	if (!RAND_bytes(&iv[0], DES_KEY_SZ))
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	return iv;
}

vector<byte> Crypto::Des::default_iv()
{
	return vector<byte>(DES_KEY_SZ);
}

vector<byte> Crypto::Des::encrypt(const vector<byte>& data, const vector<byte>& key, const MODE& mode, const PADDING& padding, const vector<byte>& iv)
{
	if (!check_key(key))
	{
		throw exception("The key is unsupported.");
	}

	if (!check_iv(iv))
	{
		throw exception("The iv is unsupported.");
	}

	int cipher_text_buffer_length = (data.size() / DES_KEY_SZ + 1) * DES_KEY_SZ;
	vector<byte> message(data);

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_CIPHER_CTX_set_padding(ctx, padding);
	const EVP_CIPHER* cipher_type = get_mode(mode, key.size() / DES_KEY_SZ);

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

vector<byte> Crypto::Des::decrypt(const vector<byte>& data, const vector<byte>& key, const MODE& mode, const PADDING& padding, const vector<byte>& iv)
{
	if (!check_key(key))
	{
		throw exception("The key is unsupported.");
	}

	if (!check_iv(iv))
	{
		throw exception("The iv is unsupported.");
	}

	if (!check_cipher_text(data))
	{
		throw exception("The length of cipher-text is error.");
	}

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_CIPHER_CTX_set_padding(ctx, padding);
	const EVP_CIPHER* cipher_type = get_mode(mode, key.size() / DES_KEY_SZ);

	vector<byte> cipher_text(data);
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
