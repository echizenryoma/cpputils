#include <vector>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include "type.h"
#include "aes.h"
#include <openssl/err.h>
using std::vector;
using std::string;
using std::exception;

const EVP_CIPHER* Crypto::Aes::get_mode(const MODE& mode, const KEY_SIZE& key_size)
{
	switch (key_size)
	{
	case AES_128:
	case AES_192:
	case AES_256:
		break;
	default:
		throw exception("The key size is unsupported.");
	}
	
	const EVP_CIPHER* cipher_mode;
	switch (mode)
	{
	case CBC:
		switch (key_size)
		{
		case AES_128:
			cipher_mode = EVP_aes_128_cbc();
			break;
		case AES_192: 
			cipher_mode = EVP_aes_192_cbc();
			break;
		case AES_256: 
			cipher_mode = EVP_aes_256_cbc();
			break;
		default: 
			throw exception("The key size is unsupported.");
		}
		break;
	case CFB:
		switch (key_size)
		{
		case AES_128:
			cipher_mode = EVP_aes_128_cfb();
			break;
		case AES_192:
			cipher_mode = EVP_aes_192_cfb();
			break;
		case AES_256:
			cipher_mode = EVP_aes_256_cfb();
			break;
		default:
			throw exception("The key size is unsupported.");
		}
		break;
	case ECB:
		switch (key_size)
		{
		case AES_128:
			cipher_mode = EVP_aes_128_ecb();
			break;
		case AES_192:
			cipher_mode = EVP_aes_192_ecb();
			break;
		case AES_256:
			cipher_mode = EVP_aes_256_ecb();
			break;
		default:
			throw exception("The key size is unsupported.");
		}
		break;
	case OFB:
		switch (key_size)
		{
		case AES_128:
			cipher_mode = EVP_aes_128_ecb();
			break;
		case AES_192:
			cipher_mode = EVP_aes_192_ecb();
			break;
		case AES_256:
			cipher_mode = EVP_aes_256_ecb();
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

bool Crypto::Aes::check_cipher_text(const vector<byte>& cipher_text)
{
	return cipher_text.size() % AES_BLOCK_SIZE == 0;
}

bool Crypto::Aes::check_key(const vector<byte>& key)
{
	return check_key_size(key.size() * 8);
}

bool Crypto::Aes::check_key_size(const size_t& key_size)
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

vector<byte> Crypto::Aes::radom_key(const KEY_SIZE& key_size)
{
	if (!check_key_size(key_size))
	{
		throw exception("The key size is unsupported.");
	}

	vector<byte> aes_key(key_size / 8);
	if (!RAND_bytes(&aes_key[0], key_size / 8))
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	return aes_key;
}

Crypto::Aes::KEY_SIZE Crypto::Aes::get_key_size(const vector<byte>& key)
{
	if (!check_key(key))
	{
		throw exception("The key is unsupported");
	}
	return get_key_size(key.size() * 8);
}

Crypto::Aes::KEY_SIZE Crypto::Aes::get_key_size(const size_t& key_size)
{
	switch (key_size)
	{
	case AES_128:
		return AES_128;
	case AES_192:
		return AES_192;
	case AES_256:
		return AES_256;
	default:
		throw exception("The key size is unsupported");
	}
}

bool Crypto::Aes::check_iv(const vector<byte>& iv)
{
	return iv.size() == AES_BLOCK_SIZE;
}

vector<byte> Crypto::Aes::radom_iv()
{
	vector<byte> iv(AES_BLOCK_SIZE);
	if (!RAND_bytes(&iv[0], AES_BLOCK_SIZE))
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	return iv;
}

vector<byte> Crypto::Aes::default_iv()
{
	return vector<byte>(AES_BLOCK_SIZE);
}

vector<byte> Crypto::Aes::encrypt(const vector<byte>& data, const vector<byte>& key, const MODE& mode, const PADDING& padding, const vector<byte> &iv)
{
	if (!check_key(key))
	{
		throw exception("The key is unsupported.");
	}

	if (!check_iv(iv))
	{
		throw exception("The iv is unsupported.");
	}

	vector<byte> message(data);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_CIPHER_CTX_set_padding(ctx, padding);
	const EVP_CIPHER* cipher_type = get_mode(mode, get_key_size(key));

	int ret = EVP_EncryptInit_ex(ctx, cipher_type, nullptr, &key[0], &iv[0]);
	if (ret <= 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}

	int cipher_text_buffer_written_length = 0;
	vector<byte> cipher_text_buffer(AES_BLOCK_SIZE);
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

vector<byte> Crypto::Aes::decrypt(const vector<byte>& data, const vector<byte>& key, const MODE& mode, const PADDING& padding, const vector<byte> &iv)
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
	const EVP_CIPHER* cipher_type = get_mode(mode, get_key_size(key));

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
